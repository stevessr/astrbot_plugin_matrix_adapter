"""RPS interactive component dispatch."""

from astrbot.api import logger


async def _dispatch_rps(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch a rock-paper-scissors component."""
    if not isinstance(segment, dispatchers["RPS"]):
        return False, False
    try:
        await dispatchers["send_rps"](
            context.client,
            segment,
            context.room_id,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.is_encrypted_room,
            context.e2ee_manager,
            context.thread_is_falling_back,
            use_notice=context.use_notice,
        )
        return True, True
    except Exception as e:
        logger.error(f"处理 RPS 消息过程出错：{e}")
    return True, False


__all__ = ["_dispatch_rps"]
