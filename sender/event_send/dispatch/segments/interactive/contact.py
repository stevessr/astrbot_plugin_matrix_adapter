"""Contact interactive component dispatch."""

from astrbot.api import logger


async def _dispatch_contact(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch a contact component."""
    if not isinstance(segment, dispatchers["Contact"]):
        return False, False
    try:
        await dispatchers["send_contact"](
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
        logger.error(f"处理联系人消息过程出错：{e}")
    return True, False


__all__ = ["_dispatch_contact"]
