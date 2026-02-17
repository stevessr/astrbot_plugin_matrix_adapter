from astrbot.api import logger
from astrbot.api.message_components import Plain

from ...constants import TEXT_TRUNCATE_LENGTH_50
from ...utils.markdown_utils import markdown_to_html
from ...utils.utils import MatrixUtils
from .common import send_content


async def send_plain(
    client,
    segment: Plain,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    original_message_info: dict | None,
    is_encrypted_room: bool,
    e2ee_manager,
    use_notice: bool,
) -> None:
    msg_type = "m.notice" if use_notice else "m.text"
    text = segment.text or ""
    content = {"msgtype": msg_type, "body": text}

    if original_message_info and reply_to:
        orig_sender = original_message_info.get("sender", "")
        orig_body = original_message_info.get("body", "")
        if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
            orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
        fallback_text = f"> <{orig_sender}> {orig_body}\n\n"
        content["body"] = fallback_text + content["body"]

    formatted_body = None
    if hasattr(segment, "formatted_body") and segment.formatted_body:
        formatted_body = segment.formatted_body
    else:
        try:
            formatted_body = markdown_to_html(text)
        except Exception as e:
            logger.warning(f"Failed to render markdown: {e}")
            formatted_body = text.replace("\n", "<br>")

    if hasattr(segment, "format") and segment.format:
        content["format"] = segment.format
    else:
        content["format"] = "org.matrix.custom.html"

    if formatted_body:
        if original_message_info and reply_to:
            fallback_html = MatrixUtils.create_reply_fallback(
                original_body=original_message_info.get("body", ""),
                original_sender=original_message_info.get("sender", ""),
                original_event_id=reply_to,
                room_id=room_id,
            )
            formatted_body = fallback_html + formatted_body
            content["format"] = "org.matrix.custom.html"

        content["formatted_body"] = formatted_body

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )
