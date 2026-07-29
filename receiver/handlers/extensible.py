"""
Handler for MSC1767 Extensible Events.

Matrix v1.7+ defines extensible event formats (MSC1767) as an alternative
to legacy msgtype-based events.  Constants are defined in ``constants.py``.
This handler tries to extract text/HTML from the extensible content keys
when no legacy ``msgtype`` is present.
"""

from astrbot.api.message_components import Plain

from ...constants import MSC1767_HTML_KEY, MSC1767_TEXT_KEY


async def handle_extensible_event(receiver, chain, event, _msgtype: str):
    """Handle an event whose type is ``m.room.message`` but whose content
    uses MSC1767 extensible keys instead of a legacy ``msgtype``."""

    content = event.content or {}

    # Try the HTML variant first, then plain text.
    html = _nested_content(content, MSC1767_HTML_KEY, "body")
    if html:
        from .text import append_formatted_text

        body = _nested_content(content, MSC1767_TEXT_KEY, "body") or event.body or ""
        append_formatted_text(receiver, chain, body, {
            "format": "org.matrix.custom.html",
            "formatted_body": html,
        })
        return

    text = _nested_content(content, MSC1767_TEXT_KEY, "body")
    if text:
        chain.chain.append(Plain(text))
        return

    # Fall back to the event body
    chain.chain.append(Plain(event.body or "[Extensible event]"))


def _nested_content(content: dict, *keys: str) -> str | None:
    """Walk nested dict keys and return the string leaf value, or None."""
    current = content
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, str) else None
