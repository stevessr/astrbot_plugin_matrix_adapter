"""Event parsing orchestration."""

from typing import Any

from ....constants import (
    M_ROOM_MESSAGE,
    REL_TYPE_REPLACE,
)
from ..base import MatrixEvent
from .location import parse_location_event
from .messages import parse_message_event
from .state import parse_state_event


def parse_event(event_data: dict[str, Any], room_id: str) -> MatrixEvent:
    """
    Parse event data into appropriate event type.

    Args:
        event_data: Raw event data from Matrix.
        room_id: Room ID the event belongs to.

    Returns:
        Parsed event object.
    """
    event_type = event_data.get("type", "")
    content = event_data.get("content", {})
    relates_to = content.get("m.relates_to", {})

    # Treat edits (m.replace) as normal messages with new content.
    if (
        event_type == M_ROOM_MESSAGE
        and relates_to.get("rel_type") == REL_TYPE_REPLACE
        and content.get("m.new_content")
    ):
        content = dict(content.get("m.new_content", {}))
        content.setdefault("m.relates_to", relates_to)
        event_data = dict(event_data)
        event_data["content"] = content

    parsed_event = parse_message_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    parsed_event = parse_location_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    parsed_event = parse_state_event(event_data, room_id, event_type, content)
    if parsed_event is not None:
        return parsed_event

    return MatrixEvent.from_dict(event_data, room_id)


__all__ = ["parse_event"]