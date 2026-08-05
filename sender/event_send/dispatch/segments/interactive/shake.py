"""Shake interactive component dispatch."""

from astrbot.api import logger


async def _dispatch_shake(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch a shake component."""
    if not isinstance(segment, dispatchers["Shake"]):
        return False, False
    try:
        await dispatchers["send_shake"](
            context.client,
            segment,
            context.room_id,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.is_encrypted_room,
            context.e2ee_manager,
            context.thread_is_falling_back,
        )
        return True, True
    except Exception as e:
        logger.error(f"处理震动消息过程出错：{e}")
    return True, False


__all__ = ["_dispatch_shake"]
