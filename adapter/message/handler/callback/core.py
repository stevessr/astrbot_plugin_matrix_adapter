"""Inbound message callback operations."""

from astrbot.api import logger

from .....constants import M_REACTION, REL_TYPE_REPLACE
from ...archive import _is_live_message_draft
from ..common import _get_plugin_config
from .convert import _convert_event
from .dispatch import _dispatch_message
from .reaction import _handle_reaction_event
from .replace import _normalize_replace_event
from .stalk import _record_stalk_archive


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
            await _handle_reaction_event(self, room, event, sender_id, sender_name)
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
            await _normalize_replace_event(self, room, event)

        # Convert the Matrix event into an AstrBot message.
        abm = await _convert_event(self, room, event)
        if abm is None:
            return

        force_message_type = _get_plugin_config().force_message_type

        if abm and force_message_type == "stalk":
            _record_stalk_archive(abm, event, sender_id, sender_name)

        await _dispatch_message(self, abm, event, room, force_message_type)
    except Exception as e:
        logger.error(f"消息回调时出错：{e}")


__all__ = ["message_callback"]
