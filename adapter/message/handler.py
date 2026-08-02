"""Matrix message callback and event conversion integration."""

import time

from astrbot.api import logger

from ...constants import (
    M_REACTION,
    M_ROOM_ENCRYPTED,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_NOTICE,
    MSGTYPE_STICKER,
    MSGTYPE_VIDEO,
    REL_TYPE_REPLACE,
)
from .archive import (
    _append_stalk_archive,
    _find_stalk_archive_message,
    _is_live_message_draft,
    _normalize_text,
)


def _get_plugin_config():
    from . import get_plugin_config

    return get_plugin_config()


class MatrixAdapterMessageMixin:
    async def _resolve_reaction_target_summary(self, room, event_id: str) -> str:
        if not event_id or not self.client:
            return ""
        try:
            event = await self.client.get_event(room.room_id, event_id)
        except Exception as e:
            logger.debug(f"获取 reaction 目标事件失败：{e}")
            event = None

        if event:
            sender_id = event.get("sender", "") or ""
            sender_name = room.members.get(sender_id, sender_id) if sender_id else ""
            event_type = event.get("type") or event.get("event_type") or ""
            content = event.get("content") or {}

            body = ""
            if event_type == M_ROOM_MESSAGE:
                msgtype = content.get("msgtype") or ""
                body = content.get("body") or ""
                if not body and msgtype in (
                    MSGTYPE_IMAGE,
                    MSGTYPE_VIDEO,
                    MSGTYPE_AUDIO,
                    MSGTYPE_FILE,
                ):
                    body = msgtype
                if msgtype == MSGTYPE_STICKER and not body:
                    body = "sticker"
            elif event_type == M_REACTION:
                reaction = content.get("m.relates_to", {}).get("key", "")
                body = f"[reaction] {reaction}".strip()
            elif event_type == M_ROOM_ENCRYPTED:
                body = "[encrypted]"
            elif event_type == M_ROOM_REDACTION:
                body = "[redaction]"
            else:
                body = (
                    content.get("body")
                    or content.get("name")
                    or content.get("topic")
                    or ""
                )

            body = _normalize_text(body)
            if sender_name and sender_id:
                sender = f"{sender_name}/{sender_id}"
            else:
                sender = sender_name or sender_id

            if sender and body:
                return f"{sender}: {body}"
            if sender:
                return sender
            if body:
                return body
            if event_type:
                return event_type

        return _find_stalk_archive_message(room.room_id, event_id)

    async def message_callback(self, room, event):
        """
        Process a message event (called by event processor after filtering)

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            runtime_state = getattr(self, "runtime_state", None)
            sender_id = getattr(event, "sender", "") or ""
            sender_name = room.members.get(sender_id, sender_id) if sender_id else ""

            if getattr(event, "msgtype", None) == M_REACTION:
                # Reactions should not enter the normal pipeline to avoid LLM replies.
                try:
                    relates_to = event.content.get("m.relates_to", {})
                    emoji = relates_to.get("key") or event.body or ""
                    target = relates_to.get("event_id", "")
                    target_summary = ""
                    if target:
                        target_summary = await self._resolve_reaction_target_summary(
                            room, target
                        )
                    if emoji and target:
                        text = f"[reaction] {emoji} -> {target}"
                    elif emoji:
                        text = f"[reaction] {emoji}"
                    elif target:
                        text = f"[reaction] -> {target}"
                    else:
                        text = "[reaction]"
                    if target_summary:
                        text = f"{text} ({target_summary})"
                    # Reaction 日志改为 debug，以减少高频 info 输出
                    logger.debug(f"[matrix(matrix)] {sender_name}/{sender_id}: {text}")
                except Exception:
                    pass
                return  # Reactions 已处理，不再进入后续消息/系统事件转换流程

            event_content = getattr(event, "content", {}) or {}
            relates_to = event_content.get("m.relates_to", {})
            if _is_live_message_draft(event):
                if runtime_state:
                    try:
                        runtime_state.mark_live_message_inbound(
                            is_edit=bool(
                                isinstance(relates_to, dict)
                                and relates_to.get("rel_type") == REL_TYPE_REPLACE
                            )
                        )
                    except Exception:
                        pass
                logger.debug(
                    f"忽略 Matrix live message 草稿/增量：event_id={getattr(event, 'event_id', '')}"
                )
                return

            if (
                isinstance(relates_to, dict)
                and relates_to.get("rel_type") == REL_TYPE_REPLACE
            ):
                if runtime_state:
                    try:
                        runtime_state.mark_live_message_inbound(is_edit=True)
                    except Exception:
                        pass

            # Convert the Matrix event into an AstrBot message.
            if getattr(event, "msgtype", None):
                abm = await self.receiver.convert_message(room, event)
            else:
                abm = await self.receiver.convert_system_event(room, event)
            if abm is None:
                logger.warning(f"转换消息失败：{event}")
                return

            force_message_type = _get_plugin_config().force_message_type

            if abm and force_message_type == "stalk":
                record = {
                    "ts": int(time.time() * 1000),
                    "room_id": abm.session_id,
                    "event_id": getattr(event, "event_id", ""),
                    "sender_id": sender_id,
                    "sender_name": sender_name,
                    "message_str": abm.message_str,
                    "message": abm.message,
                    "raw_message": abm.raw_message,
                }
                _append_stalk_archive(abm.session_id, record)

            if getattr(event, "msgtype", None) == MSGTYPE_NOTICE:
                logger.debug(
                    f"忽略 m.notice 自动分发，避免 bot notice 触发回复：event_id={getattr(event, 'event_id', '')}"
                )
                return

            if force_message_type != "stalk":
                await self.handle_msg(
                    abm,
                    event_id=getattr(event, "event_id", None),
                    room_live_messaging_enabled=getattr(
                        room,
                        "live_messaging_enabled",
                        None,
                    ),
                )
        except Exception as e:
            logger.error(f"消息回调时出错：{e}")

    async def handle_msg(
        self,
        message,
        event_id: str | None = None,
        room_live_messaging_enabled: bool | None = None,
    ):
        try:
            from ...events.matrix import MatrixPlatformEvent

            message_event = MatrixPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                client=self.client,
                enable_threading=self._matrix_config.enable_threading,
                room_live_messaging_enabled=room_live_messaging_enabled,
                live_message_update_interval_ms=getattr(
                    self._matrix_config,
                    "live_message_update_interval_ms",
                    2000,
                ),
                e2ee_manager=self.e2ee_manager,
                use_notice=self._matrix_config.use_notice,
                adaptive_thread_reply=_get_plugin_config().adaptive_thread_reply,
                send_typing=_get_plugin_config().send_typing,
            )

            self.commit_event(message_event)
            # 仅记录必要的事件元信息，避免在 debug 中打印过多用户标识
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")
