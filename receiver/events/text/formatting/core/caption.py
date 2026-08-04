"""Caption policy for formatted Matrix text."""


def should_append_caption(content: dict, filename: str | None = None) -> bool:
    body = content.get("body") or ""
    if not body:
        return False
    if content.get("formatted_body"):
        return True
    if filename and body != filename:
        return True
    return False
