"""Live Matrix message sending orchestration."""

import time

from astrbot.api.event import MessageChain

from ......constants import MSGTYPE_NOTICE, MSGTYPE_TEXT


class MatrixPlatformEventMessagesSendingCoreMixin:
    """Send live Matrix messages and preserve thread updates."""

    async def _mark_stream_operation(self, metric_cls) -> None:
        if metric_cls is not None:
            await metric_cls.upload(
                msg_event_tick=1,
                adapter_name=self.platform_meta.name,
            )
        self._has_send_oper = True

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

        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

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
                    await self._mark_stream_operation(metric_cls)
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
                        (
                            _,
                            current_event_id,
                            last_sent_text,
                            last_flush_at,
                        ) = await self._send_live_payload(
                            buffer,
                            final=True,
                            room_id=room_id,
                            msg_type=msg_type,
                            current_event_id=current_event_id,
                            last_sent_text=last_sent_text,
                            last_flush_at=last_flush_at,
                            initial_relation=initial_relation,
                            is_encrypted_room=is_encrypted_room,
                            stream_thread_root=stream_thread_root,
                        )
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
                    (
                        _,
                        current_event_id,
                        last_sent_text,
                        last_flush_at,
                    ) = await self._send_live_payload(
                        buffer,
                        final=False,
                        room_id=room_id,
                        msg_type=msg_type,
                        current_event_id=current_event_id,
                        last_sent_text=last_sent_text,
                        last_flush_at=last_flush_at,
                        initial_relation=initial_relation,
                        is_encrypted_room=is_encrypted_room,
                        stream_thread_root=stream_thread_root,
                    )

            if current_event_id is None:
                if buffer:
                    await self.send(MessageChain().message(buffer))
                    used_self_send = True
                if not used_self_send:
                    await self._mark_stream_operation(metric_cls)
                return

            if buffer != last_sent_text or last_sent_text:
                if buffer:
                    (
                        _,
                        current_event_id,
                        last_sent_text,
                        last_flush_at,
                    ) = await self._send_live_payload(
                        buffer,
                        final=True,
                        room_id=room_id,
                        msg_type=msg_type,
                        current_event_id=current_event_id,
                        last_sent_text=last_sent_text,
                        last_flush_at=last_flush_at,
                        initial_relation=initial_relation,
                        is_encrypted_room=is_encrypted_room,
                        stream_thread_root=stream_thread_root,
                    )
                else:
                    await self._mark_stream_operation(metric_cls)
            await self._mark_stream_operation(metric_cls)
        finally:
            await self._stop_typing_keepalive(typing_task, room_id)
