"""Live Matrix message streaming and thread relations."""

import html
import time

from astrbot.api import logger
from astrbot.api.event import MessageChain

from ....constants import (
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4357_LIVE_MESSAGE_MARKER,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
)
from ....sender.event_send.crypto import (
    edit_message_encrypted,
    edit_message_plain,
    send_message_encrypted,
    send_message_plain,
)
from ....utils.markdown_utils import markdown_to_html
from .. import core as _matrix_event_module


class MatrixPlatformEventMessagesMixin:
    """Send live Matrix messages and preserve thread relationships."""

    @staticmethod
    def _stream_event_module():
        """Return the current event module even after test/app reloads."""

        import sys

        package_name = __package__.rpartition(".")[0]
        package = sys.modules.get(package_name)
        return getattr(package, "core", None) or _matrix_event_module

    def _build_stream_thread_relation(self) -> dict | None:
        """Build the initial message relation for a streamed thread reply.

        Replacement events point at the initial live event with ``m.replace``;
        Matrix keeps the initial event's thread relation when applying edits.
        """

        source_event_id = self._inbound_event_id()
        if not source_event_id:
            return None

        thread_root = self._inbound_thread_root()
        if thread_root:
            # 回复自适应：入站消息已在消息列内，流式回复必须留在同一消息列。
            if not (self.adaptive_thread_reply or self.enable_threading):
                return None
        else:
            # 入站消息不在消息列内，只有显式开启线程回复才新建消息列。
            if not self.enable_threading:
                return None
            thread_root = source_event_id

        return {
            "rel_type": "m.thread",
            "event_id": thread_root,
            "is_falling_back": True,
            "m.in_reply_to": {"event_id": source_event_id},
        }

    async def send_streaming(self, generator, use_fallback: bool = False) -> None:
        """发送流式消息。

        使用 MSC4357 的初始标记与 ``m.replace`` 更新。房间明确
        禁用 Live Messages 时才聚合为普通消息。
        """

        if use_fallback:
            # 回退：缓存整个生成器然后作为一条消息发送
            full_text = ""
            async for chain in generator:
                if not isinstance(chain, MessageChain):
                    continue
                if chain.type == "break":
                    continue
                text = chain.get_plain_text()
                if text:
                    full_text += text
            if full_text:
                await self.send(MessageChain().message(full_text))
            self._has_send_oper = True
            return

        room_id = self.session_id
        msg_type = MSGTYPE_NOTICE if self.use_notice else MSGTYPE_TEXT
        buffer = ""
        current_event_id: str | None = None
        last_sent_text = ""
        last_flush_at = 0.0
        flush_interval = self.live_message_update_interval_ms / 1000
        initial_relation = self._build_stream_thread_relation()
        # MSC4145: 编辑位于消息列内的消息时，编辑事件需同时携带 m.thread 关系，
        # 保证编辑在客户端聚合在消息列内而非落到房间时间线。
        stream_thread_root = None
        if isinstance(initial_relation, dict):
            stream_thread_root = initial_relation.get("event_id")
        used_self_send = False
        is_encrypted_room = False
        metric_cls = None
        try:
            from astrbot.core.utils.metrics import Metric

            metric_cls = Metric
        except Exception:
            metric_cls = None

        async def _mark_stream_operation() -> None:
            if metric_cls is not None:
                await metric_cls.upload(
                    msg_event_tick=1,
                    adapter_name=self.platform_meta.name,
                )
            self._has_send_oper = True

        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        async def _send_live_payload(text: str, *, final: bool) -> bool:
            nonlocal current_event_id, last_sent_text, last_flush_at

            content = {
                "msgtype": msg_type,
                "body": text,
            }
            try:
                formatted_body = markdown_to_html(text)
            except Exception as e:
                logger.warning(f"Failed to render live message markdown: {e}")
                formatted_body = html.escape(text).replace("\n", "<br>")
            if formatted_body:
                content["format"] = MATRIX_HTML_FORMAT
                content["formatted_body"] = formatted_body
            if not final:
                content[MSC4357_LIVE_MESSAGE_MARKER] = {}
            if current_event_id is None and initial_relation:
                content["m.relates_to"] = dict(initial_relation)

            tracker_metadata = {
                "proposal": "msc4357-live-messages",
                "live_message": True,
                "phase": "final"
                if final
                else ("initial" if current_event_id is None else "edit"),
            }

            try:
                if current_event_id is None:
                    if is_encrypted_room:
                        response = await send_message_encrypted(
                            self.client,
                            self.e2ee_manager,
                            room_id,
                            M_ROOM_MESSAGE,
                            content,
                            tracker_metadata=tracker_metadata,
                        )
                    else:
                        response = await send_message_plain(
                            self.client,
                            room_id,
                            M_ROOM_MESSAGE,
                            content,
                            tracker_metadata=tracker_metadata,
                        )
                    event_id = (response or {}).get("event_id")
                    if not event_id:
                        raise RuntimeError(
                            "Matrix live message initial response omitted event_id"
                        )
                    current_event_id = str(event_id)
                else:
                    if is_encrypted_room:
                        await edit_message_encrypted(
                            self.client,
                            self.e2ee_manager,
                            room_id,
                            current_event_id,
                            content,
                            tracker_metadata=tracker_metadata,
                            thread_root=stream_thread_root,
                        )
                    else:
                        await edit_message_plain(
                            self.client,
                            room_id,
                            current_event_id,
                            content,
                            tracker_metadata=tracker_metadata,
                            thread_root=stream_thread_root,
                        )
            except Exception as e:
                logger.warning(f"Matrix live message update failed: {e}")
                return False

            last_sent_text = text
            last_flush_at = time.monotonic()
            return True

        # 流式生成期间持续声明 typing。生成器可能提前 return 或抛错，
        # 因此统一在 finally 中停止保活并清除状态。
        typing_task = await self._start_typing_keepalive(room_id)
        try:
            if not self.live_messages_allowed:
                async for chain in generator:
                    if not isinstance(chain, MessageChain):
                        continue
                    if chain.type == "break":
                        if buffer:
                            await self.send(MessageChain().message(buffer))
                            used_self_send = True
                            buffer = ""
                        self._response_thread_context = None
                        continue
                    text = chain.get_plain_text()
                    if text:
                        buffer += text
                if buffer:
                    await self.send(MessageChain().message(buffer))
                    used_self_send = True
                if not used_self_send:
                    await _mark_stream_operation()
                return

            async for chain in generator:
                if not isinstance(chain, MessageChain):
                    continue
                if chain.type == "break":
                    if current_event_id is None:
                        if buffer:
                            await self.send(MessageChain().message(buffer))
                            used_self_send = True
                    else:
                        await _send_live_payload(buffer, final=True)
                    self._response_thread_context = None
                    buffer = ""
                    current_event_id = None
                    last_sent_text = ""
                    last_flush_at = 0.0
                    continue

                text = chain.get_plain_text()
                if not text:
                    continue
                buffer += text

                should_flush = current_event_id is None or (
                    buffer != last_sent_text
                    and (time.monotonic() - last_flush_at) >= flush_interval
                )
                if should_flush:
                    await _send_live_payload(buffer, final=False)

            if current_event_id is None:
                if buffer:
                    await self.send(MessageChain().message(buffer))
                    used_self_send = True
                if not used_self_send:
                    await _mark_stream_operation()
                return

            if buffer != last_sent_text or last_sent_text:
                if buffer:
                    await _send_live_payload(buffer, final=True)
                else:
                    await _mark_stream_operation()
            await _mark_stream_operation()
        finally:
            await self._stop_typing_keepalive(typing_task, room_id)
