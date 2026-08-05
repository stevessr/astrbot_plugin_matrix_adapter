"""Music component dispatch."""

from astrbot.api import logger


async def _dispatch_music(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(segment, dispatchers["Music"]):
        return False, False
    try:
        await dispatchers["send_music"](
            context.client,
            segment,
            context.room_id,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.is_encrypted_room,
            context.e2ee_manager,
            context.upload_size_limit,
            context.thread_is_falling_back,
            use_notice=context.use_notice,
        )
        return True, True
    except Exception as e:
        logger.error(f"处理音乐消息过程出错：{e}")
    return True, False
