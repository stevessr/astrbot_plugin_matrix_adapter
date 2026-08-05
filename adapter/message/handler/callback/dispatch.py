"""Final dispatch for inbound callbacks."""

from astrbot.api import logger

from .....constants import MSGTYPE_NOTICE


async def _dispatch_message(adapter, abm, event, room, force_message_type: str):
    if getattr(event, "msgtype", None) == MSGTYPE_NOTICE:
        logger.debug(
            f"忽略 m.notice 自动分发，避免 bot notice 触发回复：event_id={getattr(event, 'event_id', '')}"
        )
        return

    if force_message_type != "stalk":
        await adapter.handle_msg(
            abm,
            event_id=getattr(event, "event_id", None),
            room_live_messaging_enabled=getattr(
                room,
                "live_messaging_enabled",
                None,
            ),
        )


__all__ = ["_dispatch_message"]
