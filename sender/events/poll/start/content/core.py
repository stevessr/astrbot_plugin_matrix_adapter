"""Poll start event content building."""

from .msc3381 import _build_msc3381_poll_content
from .standard import _build_standard_poll_content


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


__all__ = [
    "_build_msc3381_poll_content",
    "_build_poll_content",
    "_build_standard_poll_content",
]
