"""Location and beacon event parsing branches."""

from typing import Any

from ....constants import (
    M_BEACON,
    M_BEACON_INFO,
    MSC1767_TEXT_KEY,
    MSC3488_LOCATION_KEY,
    MSC3489_BEACON_INFO_PREFIX,
    MSC3489_BEACON_KEY,
    MSGTYPE_LOCATION,
    MSGTYPE_TEXT,
)
from ....utils.utils import _extract_text_repr
from ..base import MatrixEvent
from ..messages import RoomMessageEvent


def _build_location_body(content: dict[str, Any]) -> str:
    """Extract a human-readable body from location or beacon content."""
    for location_content in (
        content.get(MSGTYPE_LOCATION),
        content.get(MSC3488_LOCATION_KEY),
        content,
    ):
        if isinstance(location_content, dict):
            description = location_content.get("description")
            if description:
                return str(description)

    text_repr = _extract_text_repr(content.get(MSGTYPE_TEXT)) or _extract_text_repr(
        content.get(MSC1767_TEXT_KEY)
    )
    if text_repr:
        return text_repr

    for location_content in (
        content.get(MSGTYPE_LOCATION),
        content.get(MSC3488_LOCATION_KEY),
        content,
    ):
        if isinstance(location_content, dict):
            uri = location_content.get("uri") or location_content.get("geo_uri")
            if uri:
                return str(uri)

    return ""


def parse_location_event(
    event_data: dict, room_id: str, event_type: str, content: dict
) -> MatrixEvent | None:
    """Parse location and beacon events."""
    if event_type in {MSGTYPE_LOCATION, MSC3488_LOCATION_KEY}:
        location_content = dict(content)
        location_content.setdefault("msgtype", MSGTYPE_LOCATION)
        location_content.setdefault("body", _build_location_body(content))
        event_data = dict(event_data)
        event_data["content"] = location_content
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = MSGTYPE_LOCATION
        return event
    if event_type in {
        M_BEACON,
        M_BEACON_INFO,
        MSC3489_BEACON_KEY,
        MSC3489_BEACON_INFO_PREFIX,
    }:
        beacon_content = dict(content)
        beacon_content.setdefault("msgtype", M_BEACON)
        beacon_content.setdefault("body", _build_location_body(content))
        event_data = dict(event_data)
        event_data["content"] = beacon_content
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = M_BEACON
        return event
    return None
