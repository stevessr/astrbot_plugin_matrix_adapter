"""Poll and interactive component dispatch branches."""

from astrbot.api import logger


async def dispatch_interactive(context, segment, dispatchers) -> tuple[bool, bool]:
    """Dispatch polls, contacts, RPS, dice, and shake components."""
    if dispatchers["_is_poll_component"](segment):
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
                kind=getattr(segment, "kind", None)
                or dispatchers["M_POLL_KIND_DISCLOSED"],
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

    if isinstance(segment, dispatchers["Contact"]):
        try:
            await dispatchers["send_contact"](
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
            logger.error(f"处理联系人消息过程出错：{e}")
        return True, False

    if isinstance(segment, dispatchers["RPS"]):
        try:
            await dispatchers["send_rps"](
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
            logger.error(f"处理 RPS 消息过程出错：{e}")
        return True, False

    if isinstance(segment, dispatchers["Dice"]):
        try:
            await dispatchers["send_dice"](
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
            logger.error(f"处理骰子消息过程出错：{e}")
        return True, False

    if isinstance(segment, dispatchers["Shake"]):
        try:
            await dispatchers["send_shake"](
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
            logger.error(f"处理震动消息过程出错：{e}")
        return True, False

    return False, False
