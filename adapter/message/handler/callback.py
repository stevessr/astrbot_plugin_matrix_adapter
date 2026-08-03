"""Inbound message callback operations."""

import time

from astrbot.api import logger

from ....constants import M_REACTION, MSGTYPE_NOTICE, REL_TYPE_REPLACE
from ..archive import _append_stalk_archive, _is_live_message_draft
from .common import _get_plugin_config


class MatrixAdapterMessageCallbackMixin:
    """Process converted inbound Matrix messages."""

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
