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
