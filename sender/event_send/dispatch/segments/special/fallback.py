"""Compatibility fallback dispatch branch."""

from astrbot.api import logger


async def _dispatch_fallback(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(
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
        return False, False
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
