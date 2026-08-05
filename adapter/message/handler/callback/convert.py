"""Message event conversion for inbound callbacks."""

from astrbot.api import logger


async def _convert_event(adapter, room, event):
    if getattr(event, "msgtype", None):
        abm = await adapter.receiver.convert_message(room, event)
    else:
        abm = await adapter.receiver.convert_system_event(room, event)
    if abm is None:
        logger.warning(f"转换消息失败：{event}")
    return abm


__all__ = ["_convert_event"]
