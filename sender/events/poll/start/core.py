"""Matrix poll start event sender."""

from collections.abc import Awaitable, Callable

from ...common import send_content as _default_send_content
from .content import _build_poll_content
from .validate import _validate_poll_input

SendContent = Callable[..., Awaitable[dict | None]]


async def _send_poll(
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
    *,
    send_content_fn: SendContent | None = None,
) -> dict | None:
    clean_question, clean_answers, max_selections = _validate_poll_input(
        question, answers, max_selections
    )

    use_msc3381 = bool(
        (event_type or "").startswith("org.matrix.msc3381.")
        or (poll_key or "").startswith("org.matrix.msc3381.")
    )

    content = _build_poll_content(
        use_msc3381,
        clean_question=clean_question,
        clean_answers=clean_answers,
        max_selections=max_selections,
        kind=kind,
        poll_key=poll_key,
        fallback_text=fallback_text,
        fallback_html=fallback_html,
    )

    sender = send_content_fn or _default_send_content
    return await sender(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        msg_type=event_type,
        thread_is_falling_back=thread_is_falling_back,
    )
