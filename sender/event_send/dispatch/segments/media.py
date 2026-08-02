"""Media and basic component dispatch branches."""

from astrbot.api import logger


async def dispatch_media(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch image, mention, file, location, share, and music components."""
    if isinstance(segment, dispatchers["Image"]):
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

    if isinstance(segment, dispatchers["At"]):
        try:
            await dispatchers["send_at"](
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
            logger.error(f"处理 @ 消息过程出错：{e}")
        return True, False

    if isinstance(segment, dispatchers["File"]):
        try:
            await dispatchers["send_file"](
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
        except Exception as e:
            logger.error(f"处理文件消息过程出错：{e}")
        return True, False

    if isinstance(segment, dispatchers["Location"]):
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

    if isinstance(segment, dispatchers["Share"]):
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

    if isinstance(segment, dispatchers["Music"]):
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

    return False, False
