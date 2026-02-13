import html

from .common import send_content


def _build_poll_fallback(question: str, answers: list[str]) -> tuple[str, str]:
    safe_question = question.strip()
    text_lines = [safe_question] + [
        f"{idx + 1}. {ans}" for idx, ans in enumerate(answers)
    ]
    text_body = "\n".join(text_lines)

    html_items = "\n".join(f"<li>{html.escape(ans)}</li>" for ans in answers if ans)
    html_body = (
        f"<p>{html.escape(safe_question)}</p><ol>{html_items}</ol>"
        if html_items
        else f"<p>{html.escape(safe_question)}</p>"
    )
    return text_body, html_body


def _build_poll_fallback_msc1767(question: str, answers: list[str]) -> str:
    safe_question = question.strip()
    text_lines = [safe_question] + [f"{idx}. {ans}" for idx, ans in enumerate(answers)]
    return "\n".join(text_lines)


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
            {"id": f"answer_{idx + 1}", "body": ans}
            for idx, ans in enumerate(clean_answers)
        ]

        if not fallback_text or not fallback_html:
            auto_text, auto_html = _build_poll_fallback(clean_question, clean_answers)
            fallback_text = fallback_text or auto_text
            fallback_html = fallback_html or auto_html

        content = {
            poll_key: {
                "kind": kind,
                "max_selections": max_selections,
                "question": {"body": clean_question},
                "answers": answer_items,
            },
            "m.text": fallback_text,
            "m.html": fallback_html,
            "body": fallback_text,
        }

    return await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        msg_type=event_type,
    )


async def send_poll_response(
    client,
    room_id: str,
    poll_start_event_id: str,
    answer_ids: list[str],
    event_type: str = "m.poll.response",
    poll_key: str = "m.poll",
) -> dict | None:
    """Send a response to an existing poll.

    Args:
        client: Matrix HTTP client
        room_id: Room ID
        poll_start_event_id: The event ID of the poll start event
        answer_ids: List of answer IDs to vote for
        event_type: Event type to use (m.poll.response or org.matrix.msc3381.poll.response)
        poll_key: Poll key to use (m.poll or org.matrix.msc3381.poll.start)

    Returns:
        The response from the server, or None on failure
    """
    from ..common import send_content

    if not poll_start_event_id:
        raise ValueError("poll_start_event_id is required for poll response")

    clean_answer_ids = [str(a).strip() for a in (answer_ids or []) if str(a).strip()]
    if not clean_answer_ids:
        raise ValueError("at least one answer_id is required for poll response")

    use_msc3381 = bool(
        (event_type or "").startswith("org.matrix.msc3381.")
        or (poll_key or "").startswith("org.matrix.msc3381.")
    )

    if use_msc3381:
        content = {
            poll_key: {
                "answers": clean_answer_ids,
            }
        }
    else:
        content = {
            poll_key: {
                "answers": clean_answer_ids,
            }
        }

    # Send as a to-device message (relates to the poll start event)
    # We need to send this as a regular event in the room
    content["m.relates_to"] = {
        "rel_type": "m.reference",
        "event_id": poll_start_event_id,
    }

    return await send_content(
        client,
        content,
        room_id,
        reply_to=None,
        thread_root=None,
        use_thread=False,
        is_encrypted_room=False,  # Poll responses are typically not encrypted separately
        e2ee_manager=None,
        msg_type=event_type,
    )
