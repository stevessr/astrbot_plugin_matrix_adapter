"""Room state event type classification helpers."""

from .....constants import (
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
)

VISIBLE_ROOM_STATE_EVENT_TYPES = frozenset(
    {
        M_ROOM_NAME,
        M_ROOM_TOPIC,
        M_ROOM_AVATAR,
        M_ROOM_CREATE,
        M_ROOM_ENCRYPTION,
        M_ROOM_SERVER_ACL,
        M_ROOM_TOMBSTONE,
        M_ROOM_POWER_LEVELS,
        M_ROOM_JOIN_RULES,
        M_ROOM_HISTORY_VISIBILITY,
        M_ROOM_GUEST_ACCESS,
        M_ROOM_CANONICAL_ALIAS,
        M_ROOM_ALIASES,
        M_ROOM_PINNED_EVENTS,
        M_ROOM_THIRD_PARTY_INVITE,
        M_SPACE_CHILD,
        M_SPACE_PARENT,
    }
)

LIVE_MESSAGING_STATE_EVENT_TYPES = frozenset(
    {
        M_ROOM_LIVE_MESSAGING,
        MSC4357_LIVE_MESSAGING_STATE,
    }
)


def _is_room_state_event_type(event_type: str) -> bool:
    return (
        isinstance(event_type, str)
        and bool(event_type)
        and (
            event_type.startswith(("m.room.", "m.space."))
            or event_type in LIVE_MESSAGING_STATE_EVENT_TYPES
        )
    )
