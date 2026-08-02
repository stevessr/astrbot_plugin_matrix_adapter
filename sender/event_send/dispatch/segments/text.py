"""Text and reply component dispatch branches."""

from astrbot.api import logger


async def dispatch_text(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch reply/plain components and report (handled, succeeded)."""
    if isinstance(segment, dispatchers["Reply"]):
        return True, False

    if not isinstance(segment, dispatchers["Plain"]):
        return False, False

    try:
        await dispatchers["send_plain"](
            context.client,
            segment,
            context.room_id,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.original_message_info,
            context.is_encrypted_room,
            context.e2ee_manager,
            context.use_notice,
            context.thread_is_falling_back,
        )
        return True, True
    except Exception as e:
        logger.error(f"发送文本消息失败：{e}")
        return True, False
