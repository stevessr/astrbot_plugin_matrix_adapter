"""Matrix poll start event sender."""

from collections.abc import Awaitable, Callable

from ..common import send_content as _default_send_content
from .fallback import (
    _build_extensible_text,
    _build_poll_fallback,
    _build_poll_fallback_msc1767,
)

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
    clean_question = (question or "").strip()
    if not clean_question:
        raise ValueError("question is required for poll")

    clean_answers = [str(a).strip() for a in (answers or []) if str(a).strip()]
    if not clean_answers:
        raise ValueError("answers is required for poll")

    if max_selections < 1:
        max_selections = 1
    if max_selections > len(clean_answers):
        max_selections = len(clean_answers)

    use_msc3381 = bool(
        (event_type or "").startswith("org.matrix.msc3381.")
        or (poll_key or "").startswith("org.matrix.msc3381.")
    )

    if use_msc3381:
        if not fallback_text:
            fallback_text = _build_poll_fallback_msc1767(clean_question, clean_answers)
        answers = [
            {"id": str(idx + 1), "org.matrix.msc1767.text": ans}
            for idx, ans in enumerate(clean_answers)
        ]
        poll_kind = (
            "org.matrix.msc3381.poll.disclosed"
            if kind in ("m.disclosed", "org.matrix.msc3381.poll.disclosed")
            else kind
        )
        content = {
            "org.matrix.msc1767.text": fallback_text,
            poll_key: {
                "kind": poll_kind,
                "max_selections": max_selections,
                "question": {
                    "body": clean_question,
                    "msgtype": "m.text",
                    "org.matrix.msc1767.text": clean_question,
                },
                "answers": answers,
            },
        }
    else:
        answer_items = [
            {
                "id": f"answer_{idx + 1}",
                "m.id": f"answer_{idx + 1}",
                "body": ans,
                "m.text": _build_extensible_text(ans),
            }
            for idx, ans in enumerate(clean_answers)
        ]

        if not fallback_text or not fallback_html:
            auto_text, auto_html = _build_poll_fallback(clean_question, clean_answers)
            fallback_text = fallback_text or auto_text
            fallback_html = fallback_html or auto_html

        fallback_m_text = _build_extensible_text(fallback_text)
        if fallback_html:
            fallback_m_text.append({"body": fallback_html, "mimetype": "text/html"})

        content = {
            poll_key: {
                "kind": kind,
                "max_selections": max_selections,
                "question": {
                    "body": clean_question,
                    "m.text": _build_extensible_text(clean_question),
                },
                "answers": answer_items,
            },
            "m.text": fallback_m_text,
            "m.html": fallback_html,
            "body": fallback_text,
        }

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
