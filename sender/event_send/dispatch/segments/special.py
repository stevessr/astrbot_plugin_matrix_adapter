"""Special, voice, sticker, and compatibility fallback branches."""

from astrbot.api import logger


async def dispatch_special(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch video, record, sticker, poke, and fallback components."""
    if isinstance(segment, dispatchers["Video"]):
        try:
            await dispatchers["send_video"](
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
            logger.error(f"处理视频消息过程出错：{e}")
        return True, False

    if dispatchers["is_record_component"](segment):
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

    if dispatchers["_is_sticker_component"](segment):
        try:
            await dispatchers["send_sticker"](
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
            logger.error(f"发送 sticker 失败：{e}")
        return True, False

    if isinstance(segment, dispatchers["Poke"]):
        try:
            content_data = {
                "msgtype": dispatchers["MSGTYPE_EMOTE"],
                "body": "pokes",
            }
            await dispatchers["send_content"](
                context.client,
                content_data,
                context.room_id,
                context.reply_to,
                context.thread_root,
                context.use_thread,
                context.is_encrypted_room,
                context.e2ee_manager,
                thread_is_falling_back=context.thread_is_falling_back,
            )
            return True, True
        except Exception as e:
            logger.error(f"发送 poke 失败：{e}")
        return True, False

    if isinstance(
        segment,
        (
            dispatchers["Face"],
            dispatchers["Forward"],
            dispatchers["Node"],
            dispatchers["Nodes"],
            dispatchers["Json"],
            dispatchers["Unknown"],
        ),
    ):
        try:
            fallback_text, fallback_html = dispatchers["_fallback_content_for_segment"](
                segment
            )
            if fallback_html:
                temp = dispatchers["Plain"](
                    text=fallback_text,
                    format=dispatchers["MATRIX_HTML_FORMAT"],
                    formatted_body=fallback_html,
                    convert=False,
                )
            else:
                temp = dispatchers["Plain"](fallback_text)
            await dispatchers["send_plain"](
                context.client,
                temp,
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
            logger.error(f"发送兼容消息失败：{e}")
        return True, False

    return False, False
