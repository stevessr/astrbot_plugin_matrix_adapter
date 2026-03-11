"""Handler for Matrix poll events."""

from astrbot.api.message_components import Plain


def _get_poll_content(content: dict) -> dict:
    return content.get("m.poll", {}) or content.get("org.matrix.msc3381.poll.start", {})


def _extract_poll_answers(answers: list) -> list[str]:
    result: list[str] = []
    for answer in answers or []:
        if isinstance(answer, dict):
            body = answer.get("body") or answer.get("org.matrix.msc1767.text")
            if body:
                result.append(str(body))
        elif answer:
            result.append(str(answer))
    return result


async def handle_poll_start(receiver, chain, event, _: str):
    """Handle m.poll.start / org.matrix.msc3381.poll.start events."""
    content = event.content or {}
    poll = _get_poll_content(content)

    question = (
        poll.get("question", {}).get("body")
        or content.get("m.text")
        or content.get("body")
        or content.get("org.matrix.msc1767.text")
        or ""
    )
    answers = _extract_poll_answers(poll.get("answers", []))

    text = f"[Poll] {question}" if question else "[Poll]"
    if answers:
        text += f" | Options: {', '.join(answers)}"

    chain.chain.append(Plain(text))


async def handle_poll_response(receiver, chain, event, _: str):
    """
    Handle m.poll.response event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}

    # Get the poll response details
    relates_to = content.get("m.relates_to", {})
    poll_start_id = relates_to.get("event_id", "")

    # Get selected answers (Matrix spec: m.selections is a list of answer IDs)
    poll_response = content.get("m.poll.response", {}) or content.get(
        "org.matrix.msc3381.poll.response", {}
    )
    selections = poll_response.get("answers", [])

    # Build a text representation
    if selections:
        selection_text = ", ".join(str(s) for s in selections)
        text = f"[Poll Response] Selected: {selection_text}"
    else:
        text = "[Poll Response] (no selection)"

    if poll_start_id:
        text += f" (responding to {(poll_start_id or '')[:16]}...)"

    chain.chain.append(Plain(text))


async def handle_poll_end(receiver, chain, event, _: str):
    """
    Handle m.poll.end event

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        _: Event type (unused)
    """
    content = event.content or {}

    # Get the poll that is being ended
    relates_to = content.get("m.relates_to", {})
    poll_start_id = relates_to.get("event_id", "")

    # Get poll end text
    content.get("m.poll.end", {}) or content.get("org.matrix.msc3381.poll.end", {})

    # The m.text field contains a summary of the poll results
    text_content = content.get("m.text", "") or content.get("body", "")

    if text_content:
        text = f"[Poll Ended] {text_content}"
    else:
        text = "[Poll Ended]"

    if poll_start_id:
        text += f" (poll: {(poll_start_id or '')[:16]}...)"

    chain.chain.append(Plain(text))
