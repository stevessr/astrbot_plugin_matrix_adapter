"""MSC3381 poll content building."""

from ...fallback import _build_poll_fallback_msc1767


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


__all__ = ["_build_msc3381_poll_content"]
