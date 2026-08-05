"""Legacy reply fallback rendering for plain text sends."""

from ....constants import TEXT_TRUNCATE_LENGTH_50
from ....utils.utils import MatrixUtils


def _build_reply_fallback_text(original_message_info: dict | None) -> str:
    orig_sender = original_message_info.get("sender", "")
    orig_body = original_message_info.get("body", "")
    if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
        orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
    return f"> <{orig_sender}> {orig_body}\n\n"


def _build_reply_fallback_html(
    original_message_info: dict | None, reply_to: str, room_id: str
) -> str:
    return MatrixUtils.create_reply_fallback(
        original_body=original_message_info.get("body", ""),
        original_sender=original_message_info.get("sender", ""),
        original_event_id=reply_to,
        room_id=room_id,
    )


__all__ = ["_build_reply_fallback_html", "_build_reply_fallback_text"]
