"""Poll content extraction helpers."""


def _get_poll_content(content: dict) -> dict:
    return content.get("m.poll", {}) or content.get("org.matrix.msc3381.poll.start", {})


def _extract_text_repr(value) -> str:
    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        body = value.get("body")
        return str(body) if body else ""

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                body = item.get("body")
                mimetype = item.get("mimetype")
                if body and mimetype in (None, "", "text/plain"):
                    return str(body)
            elif item:
                return str(item)

    return ""


def _extract_poll_answers(answers: list) -> list[str]:
    result: list[str] = []
    for answer in answers or []:
        if isinstance(answer, dict):
            body = (
                answer.get("body")
                or _extract_text_repr(answer.get("m.text"))
                or answer.get("org.matrix.msc1767.text")
            )
            if body:
                result.append(str(body))
        elif answer:
            result.append(str(answer))
    return result


def _extract_poll_selections(content: dict) -> list[str]:
    selections = content.get("m.selections")
    if isinstance(selections, list):
        return [str(selection) for selection in selections if selection]
    if selections:
        return [str(selections)]

    poll_response = content.get("m.poll.response", {}) or content.get(
        "org.matrix.msc3381.poll.response", {}
    )
    if isinstance(poll_response, dict):
        answers = poll_response.get("answers", [])
        if isinstance(answers, list):
            return [str(answer) for answer in answers if answer]
        if answers:
            return [str(answers)]

    return []
