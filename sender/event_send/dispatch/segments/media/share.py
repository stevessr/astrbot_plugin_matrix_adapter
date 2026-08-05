"""Share component dispatch."""

from astrbot.api import logger


async def _dispatch_share(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(segment, dispatchers["Share"]):
        return False, False
    try:
        await dispatchers["send_share"](
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
        logger.error(f"处理分享消息过程出错：{e}")
    return True, False
