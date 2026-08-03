"""Helpers shared by Matrix receiver conversion operations."""

from .....constants import MSC1767_HTML_KEY, MSC1767_TEXT_KEY


def _has_extensible_content(content: dict | None) -> bool:
    """Check if event content uses MSC1767 extensible event keys."""
    if not isinstance(content, dict):
        return False
    for key in (MSC1767_TEXT_KEY, MSC1767_HTML_KEY):
        if isinstance(content.get(key), dict):
            return True
    return False
