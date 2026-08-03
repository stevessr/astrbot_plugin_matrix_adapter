"""Composable Matrix room event dispatch operations."""

import asyncio  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....client.event_types import parse_event  # noqa: F401
from ....constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MEMBERSHIP_JOIN,
)  # noqa: F401
from ....events.call import is_call_event_type  # noqa: F401
from ..states import (  # noqa: F401
    VISIBLE_ROOM_STATE_EVENT_TYPES,
    _is_room_state_event_type,
)
from .dispatch import (
    MatrixEventProcessorRoomDispatchMixin as MatrixEventProcessorRoomDispatchCoreMixin,
)
from .events import MatrixEventProcessorRoomEventsMixin


class MatrixEventProcessorRoomDispatchMixin(
    MatrixEventProcessorRoomDispatchCoreMixin,
    MatrixEventProcessorRoomEventsMixin,
):
    """Mixin for room event dispatch."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixEventProcessorRoomDispatchMixin.process_room_events = (
    MatrixEventProcessorRoomDispatchCoreMixin.__dict__["process_room_events"]
)
MatrixEventProcessorRoomDispatchMixin._handle_event = (
    MatrixEventProcessorRoomEventsMixin.__dict__["_handle_event"]
)


__all__ = [
    "MEMBERSHIP_JOIN",
    "M_ROOM_ENCRYPTED",
    "M_ROOM_ENCRYPTION",
    "M_ROOM_HISTORY_VISIBILITY",
    "M_ROOM_MEMBER",
    "M_ROOM_MESSAGE",
    "M_ROOM_REDACTION",
    "MatrixEventProcessorRoomDispatchMixin",
    "VISIBLE_ROOM_STATE_EVENT_TYPES",
    "asyncio",
    "is_call_event_type",
    "logger",
    "parse_event",
]
