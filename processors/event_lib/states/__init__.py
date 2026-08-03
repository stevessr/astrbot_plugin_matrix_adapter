"""Composable Matrix room state event processor operations."""

import asyncio  # noqa: F401

from astrbot.api import logger  # noqa: F401

from ....client.event_types import parse_event  # noqa: F401
from ....constants import (
    M_ROOM_ALIASES,
    M_ROOM_AVATAR,
    M_ROOM_CANONICAL_ALIAS,
    M_ROOM_CREATE,
    M_ROOM_ENCRYPTION,
    M_ROOM_GUEST_ACCESS,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_JOIN_RULES,
    M_ROOM_LIVE_MESSAGING,
    M_ROOM_NAME,
    M_ROOM_PINNED_EVENTS,
    M_ROOM_POWER_LEVELS,
    M_ROOM_SERVER_ACL,
    M_ROOM_THIRD_PARTY_INVITE,
    M_ROOM_TOMBSTONE,
    M_ROOM_TOPIC,
    M_SPACE_CHILD,
    M_SPACE_PARENT,
    MSC4357_LIVE_MESSAGING_STATE,
    TIMESTAMP_BUFFER_MS_1000,
)  # noqa: F401
from .calls import MatrixEventProcessorCallsMixin
from .membership import MatrixEventProcessorMembershipMixin
from .persistence import (
    LIVE_MESSAGING_STATE_EVENT_TYPES,
    VISIBLE_ROOM_STATE_EVENT_TYPES,
    MatrixEventProcessorPersistenceMixin,
    _is_room_state_event_type,
)
from .room_events import MatrixEventProcessorRoomStateMixin
from .verification import MatrixEventProcessorVerificationMixin


class MatrixEventProcessorStatesMixin(
    MatrixEventProcessorPersistenceMixin,
    MatrixEventProcessorMembershipMixin,
    MatrixEventProcessorRoomStateMixin,
    MatrixEventProcessorCallsMixin,
    MatrixEventProcessorVerificationMixin,
):
    """Mixin for room state event processing."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MatrixEventProcessorStatesMixin._persist_room_state = (
    MatrixEventProcessorPersistenceMixin.__dict__["_persist_room_state"]
)
MatrixEventProcessorStatesMixin._apply_room_state_event = (
    MatrixEventProcessorPersistenceMixin.__dict__["_apply_room_state_event"]
)
MatrixEventProcessorStatesMixin._process_member_event = (
    MatrixEventProcessorMembershipMixin.__dict__["_process_member_event"]
)
MatrixEventProcessorStatesMixin._process_room_state_event = (
    MatrixEventProcessorRoomStateMixin.__dict__["_process_room_state_event"]
)
MatrixEventProcessorStatesMixin._process_call_event = (
    MatrixEventProcessorCallsMixin.__dict__["_process_call_event"]
)
MatrixEventProcessorStatesMixin._handle_in_room_verification = (
    MatrixEventProcessorVerificationMixin.__dict__["_handle_in_room_verification"]
)


__all__ = [
    "LIVE_MESSAGING_STATE_EVENT_TYPES",
    "M_ROOM_ALIASES",
    "M_ROOM_AVATAR",
    "M_ROOM_CANONICAL_ALIAS",
    "M_ROOM_CREATE",
    "M_ROOM_ENCRYPTION",
    "M_ROOM_GUEST_ACCESS",
    "M_ROOM_HISTORY_VISIBILITY",
    "M_ROOM_JOIN_RULES",
    "M_ROOM_LIVE_MESSAGING",
    "M_ROOM_NAME",
    "M_ROOM_PINNED_EVENTS",
    "M_ROOM_POWER_LEVELS",
    "M_ROOM_SERVER_ACL",
    "M_ROOM_THIRD_PARTY_INVITE",
    "M_ROOM_TOMBSTONE",
    "M_ROOM_TOPIC",
    "M_SPACE_CHILD",
    "M_SPACE_PARENT",
    "MSC4357_LIVE_MESSAGING_STATE",
    "MatrixEventProcessorStatesMixin",
    "_is_room_state_event_type",
    "TIMESTAMP_BUFFER_MS_1000",
    "VISIBLE_ROOM_STATE_EVENT_TYPES",
    "asyncio",
    "logger",
    "parse_event",
]
