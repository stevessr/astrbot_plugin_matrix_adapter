"""Poke component dispatch branch."""

from astrbot.api import logger


async def _dispatch_poke(context, segment, dispatchers) -> tuple[bool, bool]:
    if not isinstance(segment, dispatchers["Poke"]):
        return False, False
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
