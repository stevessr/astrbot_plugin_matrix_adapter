from astrbot.api import logger
from astrbot.api.message_components import Plain

from ...constants import TEXT_TRUNCATE_LENGTH_50
from ...utils.markdown_utils import markdown_to_html
from ...utils.utils import MatrixUtils
from .common import send_content


def _merge_reply_mentions(
    content: dict, client, original_message_info: dict | None
) -> None:
    if not isinstance(original_message_info, dict):
        return

    existing_mentions = content.get("m.mentions")
    existing_user_ids = []
    room_mention = False
    if isinstance(existing_mentions, dict):
        existing_user_ids = list(existing_mentions.get("user_ids") or [])
        room_mention = bool(existing_mentions.get("room"))

    current_user_id = getattr(client, "user_id", None)
    merged_user_ids: list[str] = []

    def _add_user_id(user_id: str | None) -> None:
        if not user_id or not isinstance(user_id, str):
            return
        if current_user_id and user_id == current_user_id:
            return
        if user_id not in merged_user_ids:
            merged_user_ids.append(user_id)

    _add_user_id(original_message_info.get("sender"))

    original_mentions = original_message_info.get("mentions")
    if isinstance(original_mentions, dict):
        for user_id in original_mentions.get("user_ids") or []:
            _add_user_id(user_id)

    for user_id in existing_user_ids:
        _add_user_id(user_id)

    if merged_user_ids or room_mention:
        mentions: dict[str, object] = {}
        if merged_user_ids:
            mentions["user_ids"] = merged_user_ids
        if room_mention:
            mentions["room"] = True
        content["m.mentions"] = mentions


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
        _merge_reply_mentions(content, client, original_message_info)

    if original_message_info and reply_to and not use_thread:
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
        if original_message_info and reply_to and not use_thread:
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
