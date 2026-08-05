"""Poll start event content building."""

from ..fallback import (
    _build_extensible_text,
    _build_poll_fallback,
    _build_poll_fallback_msc1767,
)


def _build_msc3381_poll_content(
    clean_question: str,
    clean_answers: list[str],
    max_selections: int,
    kind: str,
    poll_key: str,
    fallback_text: str | None,
) -> dict:
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
    return {
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


def _build_standard_poll_content(
    clean_question: str,
    clean_answers: list[str],
    max_selections: int,
    kind: str,
    poll_key: str,
    fallback_text: str | None,
    fallback_html: str | None,
) -> dict:
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

    return {
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


def _build_poll_content(
    use_msc3381: bool,
    *,
    clean_question: str,
    clean_answers: list[str],
    max_selections: int,
    kind: str,
    poll_key: str,
    fallback_text: str | None,
    fallback_html: str | None,
) -> dict:
    if use_msc3381:
        return _build_msc3381_poll_content(
            clean_question,
            clean_answers,
            max_selections,
            kind,
            poll_key,
            fallback_text,
        )
    return _build_standard_poll_content(
        clean_question,
        clean_answers,
        max_selections,
        kind,
        poll_key,
        fallback_text,
        fallback_html,
    )
