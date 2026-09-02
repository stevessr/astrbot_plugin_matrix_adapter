import html

from astrbot.api import logger
from astrbot.api.message_components import Plain

from ....constants import MATRIX_HTML_FORMAT
from ....utils.markdown_utils import markdown_to_html
from ..common import resolve_text_msgtype, send_content
from .mentions import _merge_reply_mentions


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
    thread_is_falling_back: bool | None = None,
) -> None:
    msg_type = resolve_text_msgtype(use_notice)
    text = segment.text or ""
    content = {"msgtype": msg_type, "body": text}

    is_explicit_reply = bool(reply_to) and not (use_thread and thread_is_falling_back)
    if original_message_info and is_explicit_reply:
        _merge_reply_mentions(content, client, original_message_info)

    # Matrix v1.13 / MSC2781 removed reply fallbacks from the specification.
    # Do not copy the replied-to event into body/formatted_body: the relation
    # added by send_content() is the reply. Receive-side fallback stripping is
    # intentionally retained for historical events and older clients.
    formatted_body = None
    if hasattr(segment, "formatted_body") and segment.formatted_body:
        formatted_body = segment.formatted_body
    else:
        try:
            formatted_body = markdown_to_html(text)
        except Exception as e:
            logger.warning(f"Failed to render markdown: {e}")
            formatted_body = html.escape(text).replace("\n", "<br>")

    if hasattr(segment, "format") and segment.format:
        content["format"] = segment.format
    else:
        content["format"] = MATRIX_HTML_FORMAT

    if formatted_body:
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
        thread_is_falling_back=thread_is_falling_back,
    )


__all__ = ["send_plain"]
