"""Record (voice) component dispatch branch."""

from astrbot.api import logger


async def _dispatch_record(context, segment, dispatchers) -> tuple[bool, bool]:
    if not dispatchers["is_record_component"](segment):
        return False, False
    try:
        record_segment = dispatchers["coerce_record_component"](segment)
        if record_segment is None:
            logger.error("处理语音消息失败：无法解析 Record 组件内容")
            return True, False
        await dispatchers["send_audio"](
            context.client,
            record_segment,
            context.room_id,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.is_encrypted_room,
            context.e2ee_manager,
            context.upload_size_limit,
            context.thread_is_falling_back,
        )
        return True, True
    except Exception as e:
        logger.error(f"处理语音消息过程出错：{e}")
    return True, False
