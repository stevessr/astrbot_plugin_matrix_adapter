"""Live-message metadata helpers shared by send operations."""

from typing import Any

from ....constants import MSC4357_LIVE_MESSAGE_MARKER, REL_TYPE_REPLACE


def _content_has_live_marker(content: dict[str, Any]) -> bool:
    if not isinstance(content, dict):
        return False
    if content.get(MSC4357_LIVE_MESSAGE_MARKER) is not None:
        return True
    new_content = content.get("m.new_content")
    return isinstance(new_content, dict) and (
        new_content.get(MSC4357_LIVE_MESSAGE_MARKER) is not None
    )


def _content_is_edit(content: dict[str, Any]) -> bool:
    if not isinstance(content, dict):
        return False
    relates_to = content.get("m.relates_to")
    return (
        isinstance(relates_to, dict) and relates_to.get("rel_type") == REL_TYPE_REPLACE
    )


def _build_live_message_metadata(
    content: dict[str, Any], *, phase: str | None = None
) -> dict[str, Any] | None:
    if not isinstance(content, dict):
        return None
    if not _content_has_live_marker(content):
        return None
    metadata: dict[str, Any] = {
        "proposal": "msc4357-live-messages",
        "live_message": True,
    }
    if phase:
        metadata["phase"] = phase
    elif _content_is_edit(content):
        metadata["phase"] = "edit"
    else:
        metadata["phase"] = "initial"
    return metadata


__all__ = [
    "_content_has_live_marker",
    "_content_is_edit",
    "_build_live_message_metadata",
]
