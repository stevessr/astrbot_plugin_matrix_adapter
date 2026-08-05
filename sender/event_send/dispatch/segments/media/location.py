"""Location component dispatch."""

from astrbot.api import logger


async def _dispatch_location(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(segment, dispatchers["Location"]):
        return False, False
    try:
        await dispatchers["send_location"](
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
        logger.error(f"处理位置消息过程出错：{e}")
    return True, False
