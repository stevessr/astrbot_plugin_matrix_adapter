"""Poll interactive component dispatch."""

from astrbot.api import logger


async def _dispatch_poll(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch a poll component."""
    try:
        # 仅记录投票摘要与选项数量，避免在日志中泄露完整选项列表
        question_summary = dispatchers["_truncate_text"](
            getattr(segment, "question", "") or "", max_len=120
        )
        answers_count = len(getattr(segment, "answers", []) or [])
        logger.debug(
            f"发送投票消息：question={question_summary}, answers_count={answers_count}"
        )
        await dispatchers["send_poll"](
            context.client,
            context.room_id,
            segment.question,
            segment.answers,
            context.reply_to,
            context.thread_root,
            context.use_thread,
            context.is_encrypted_room,
            context.e2ee_manager,
            max_selections=getattr(segment, "max_selections", 1) or 1,
            kind=getattr(segment, "kind", None) or dispatchers["M_POLL_KIND_DISCLOSED"],
            event_type=getattr(segment, "event_type", None)
            or dispatchers["M_POLL_START"],
            poll_key=getattr(segment, "poll_key", None) or dispatchers["M_POLL"],
            fallback_text=getattr(segment, "fallback_text", None),
            fallback_html=getattr(segment, "fallback_html", None),
            thread_is_falling_back=context.thread_is_falling_back,
        )
        return True, True
    except Exception as e:
        logger.error(f"处理投票消息过程出错：{e}")
    return True, False


__all__ = ["_dispatch_poll"]
