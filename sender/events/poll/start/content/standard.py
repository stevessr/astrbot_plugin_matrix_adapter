"""Standard poll content building."""

from ...fallback import _build_extensible_text, _build_poll_fallback


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


__all__ = ["_build_standard_poll_content"]
