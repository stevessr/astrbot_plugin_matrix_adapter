"""Convert raw Matrix sync events into typed event models."""

from typing import Any

from ...constants import (
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
from ...utils.utils import _extract_text_repr
from .base import MatrixEvent
from .messages import (
    InviteEvent,
    RoomMessageEvent,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageText,
)


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

    if event_type == M_ROOM_MESSAGE:
        msgtype = content.get("msgtype", "")
        if msgtype == MSGTYPE_TEXT:
            return RoomMessageText.from_dict(event_data, room_id)
        if msgtype == MSGTYPE_IMAGE:
            return RoomMessageImage.from_dict(event_data, room_id)
        if msgtype == MSGTYPE_FILE:
            return RoomMessageFile.from_dict(event_data, room_id)
        return RoomMessageEvent.from_dict(event_data, room_id)
    if event_type == MSGTYPE_STICKER:
        # 贴纸事件使用 RoomMessageEvent 结构，设置 msgtype 为 m.sticker
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = MSGTYPE_STICKER
        # 确保 content 中的 msgtype 也被设置（用于接收器处理）
        if "msgtype" not in event.content:
            event.content["msgtype"] = MSGTYPE_STICKER
        return event
    if event_type == M_REACTION:
        reaction = content.get("m.relates_to", {}).get("key", "")
        reaction_content = dict(content)
        reaction_content["msgtype"] = M_REACTION
        reaction_content["body"] = reaction
        event_data = dict(event_data)
        event_data["content"] = reaction_content
        return RoomMessageEvent.from_dict(event_data, room_id)
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
    if event_type == M_ROOM_MEMBER and content.get("membership") == MEMBERSHIP_INVITE:
        return InviteEvent.from_dict(event_data, room_id)
    if event_type == M_ROOM_REDACTION:
        redaction_content = dict(content)
        if "redacts" not in redaction_content and event_data.get("redacts"):
            redaction_content["redacts"] = event_data.get("redacts")
        event_data = dict(event_data)
        event_data["content"] = redaction_content
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = "m.redaction"
        event.body = redaction_content.get("reason", "")
        return event
    return MatrixEvent.from_dict(event_data, room_id)
