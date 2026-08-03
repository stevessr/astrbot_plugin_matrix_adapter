"""Convert raw Matrix sync events into typed event models."""

from typing import Any

from ....constants import (
    M_BEACON,
    M_BEACON_INFO,
    M_REACTION,
    M_ROOM_MEMBER,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MEMBERSHIP_INVITE,
    MSC1767_TEXT_KEY,
    MSC3488_LOCATION_KEY,
    MSC3489_BEACON_INFO_PREFIX,
    MSC3489_BEACON_KEY,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_LOCATION,
    MSGTYPE_STICKER,
    MSGTYPE_TEXT,
    REL_TYPE_REPLACE,
)
from ....utils.utils import _extract_text_repr
from ..base import MatrixEvent
from ..messages import (
    InviteEvent,
    RoomMessageEvent,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageText,
)
from .location import _build_location_body, parse_location_event
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


__all__ = [
    "Any",
    "InviteEvent",
    "MEMBERSHIP_INVITE",
    "M_BEACON",
    "M_BEACON_INFO",
    "M_REACTION",
    "M_ROOM_MEMBER",
    "M_ROOM_MESSAGE",
    "M_ROOM_REDACTION",
    "MSC1767_TEXT_KEY",
    "MSC3488_LOCATION_KEY",
    "MSC3489_BEACON_INFO_PREFIX",
    "MSC3489_BEACON_KEY",
    "MSGTYPE_FILE",
    "MSGTYPE_IMAGE",
    "MSGTYPE_LOCATION",
    "MSGTYPE_STICKER",
    "MSGTYPE_TEXT",
    "MatrixEvent",
    "REL_TYPE_REPLACE",
    "RoomMessageEvent",
    "RoomMessageFile",
    "RoomMessageImage",
    "RoomMessageText",
    "_build_location_body",
    "_extract_text_repr",
    "parse_event",
    "parse_location_event",
    "parse_message_event",
    "parse_state_event",
]
