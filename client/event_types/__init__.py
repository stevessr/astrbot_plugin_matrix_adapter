"""Typed Matrix event and room models.

The package keeps the public ``client.event_types`` API while separating
models from raw-event parsing and room metadata.
"""

from .base import MatrixEvent
from .messages import (
    InviteEvent,
    RoomMessageEvent,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageText,
)
from .parser import parse_event
from .room import MatrixRoom

__all__ = [
    "InviteEvent",
    "MatrixEvent",
    "MatrixRoom",
    "RoomMessageEvent",
    "RoomMessageFile",
    "RoomMessageImage",
    "RoomMessageText",
    "parse_event",
]
