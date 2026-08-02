"""Matrix room message and membership event models."""

from dataclasses import dataclass
from typing import Any

from ...constants import (
    M_ROOM_MEMBER,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_TEXT,
)
from .base import MatrixEvent


@dataclass
class RoomMessageEvent(MatrixEvent):
    """Room message event (m.room.message)."""

    msgtype: str = ""
    body: str = ""
    url: str | None = None
    info: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        """Create room message event from dictionary."""
        content = data.get("content", {})
        return cls(
            event_id=data.get("event_id", ""),
            sender=data.get("sender", ""),
            origin_server_ts=data.get("origin_server_ts", 0),
            room_id=room_id,
            content=content,
            event_type=data.get("type", ""),
            state_key=data.get("state_key"),
            unsigned=data.get("unsigned"),
            msgtype=content.get("msgtype", ""),
            body=content.get("body", ""),
            url=content.get("url"),
            info=content.get("info"),
        )


@dataclass
class RoomMessageText(RoomMessageEvent):
    """Text message event."""

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        event = super().from_dict(data, room_id)
        event.msgtype = MSGTYPE_TEXT
        return event


@dataclass
class RoomMessageImage(RoomMessageEvent):
    """Image message event."""

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        event = super().from_dict(data, room_id)
        event.msgtype = MSGTYPE_IMAGE
        return event


@dataclass
class RoomMessageFile(RoomMessageEvent):
    """File message event."""

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        event = super().from_dict(data, room_id)
        event.msgtype = MSGTYPE_FILE
        return event


@dataclass
class InviteEvent(MatrixEvent):
    """Room invite event."""

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        """Create invite event from dictionary."""
        return cls(
            event_id=data.get("event_id", ""),
            sender=data.get("sender", ""),
            origin_server_ts=data.get("origin_server_ts", 0),
            room_id=room_id,
            content=data.get("content", {}),
            event_type=M_ROOM_MEMBER,
            state_key=data.get("state_key"),
            unsigned=data.get("unsigned"),
        )
