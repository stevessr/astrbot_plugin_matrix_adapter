"""Outbound Matrix poll event helpers."""

import html

from ....constants import CONTENT_KEY_RELATES_TO, REL_TYPE_REFERENCE
from ..common import send_content
from .fallback import (
    _build_extensible_text,
    _build_poll_fallback,
    _build_poll_fallback_msc1767,
)
from .response import _send_poll_response
from .start import _send_poll


async def send_poll(
    client,
    room_id: str,
    question: str,
    answers: list[str],
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    max_selections: int = 1,
    kind: str = "m.disclosed",
    event_type: str = "m.poll.start",
    poll_key: str = "m.poll",
    fallback_text: str | None = None,
    fallback_html: str | None = None,
    thread_is_falling_back: bool | None = None,
) -> dict | None:
    """Send a Matrix poll start event."""
    return await _send_poll(
        client,
        room_id,
        question,
        answers,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        max_selections=max_selections,
        kind=kind,
        event_type=event_type,
        poll_key=poll_key,
        fallback_text=fallback_text,
        fallback_html=fallback_html,
        thread_is_falling_back=thread_is_falling_back,
        send_content_fn=send_content,
    )


async def send_poll_response(
    client,
    room_id: str,
    poll_start_event_id: str,
    answer_ids: list[str],
    event_type: str = "m.poll.response",
    poll_key: str = "m.poll",
) -> dict | None:
    """Send a response to an existing poll."""
    return await _send_poll_response(
        client,
        room_id,
        poll_start_event_id,
        answer_ids,
        event_type=event_type,
        poll_key=poll_key,
        send_content_fn=send_content,
    )


__all__ = [
    "CONTENT_KEY_RELATES_TO",
    "REL_TYPE_REFERENCE",
    "_build_extensible_text",
    "_build_poll_fallback",
    "_build_poll_fallback_msc1767",
    "html",
    "send_content",
    "send_poll",
    "send_poll_response",
]
