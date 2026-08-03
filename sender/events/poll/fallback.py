"""Fallback payload builders for Matrix polls."""

import html


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
    text_lines = [safe_question] + [
        f"{idx + 1}. {ans}" for idx, ans in enumerate(answers)
    ]
    return "\n".join(text_lines)


def _build_extensible_text(
    body: str, mimetype: str | None = None
) -> list[dict[str, str]]:
    text = {"body": body}
    if mimetype:
        text["mimetype"] = mimetype
    return [text]
