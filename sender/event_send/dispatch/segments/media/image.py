"""Image component dispatch."""

from astrbot.api import logger


async def _dispatch_image(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(segment, dispatchers["Image"]):
        return False, False
    try:
        await dispatchers["send_image"](
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
        )
        return True, True
    except ValueError as e:
        if dispatchers["_is_media_security_validation_error"](e):
            logger.warning(f"跳过图片消息（媒体校验失败）：{e}")
        else:
            logger.error(f"发送图片消息失败：{e}")
    except Exception as e:
        logger.error(f"发送图片消息失败：{e}")
    return True, False
