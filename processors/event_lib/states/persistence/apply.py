"""In-memory application of room state events."""

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
    M_ROOM_THIRD_PARTY_INVITE,
    M_ROOM_TOMBSTONE,
    M_ROOM_TOPIC,
    M_SPACE_CHILD,
    M_SPACE_PARENT,
    MSC4357_LIVE_MESSAGING_STATE,
)
from .....room_topic import extract_room_topic
from .types import (
    LIVE_MESSAGING_STATE_EVENT_TYPES,
    _is_room_state_event_type,
)


class MatrixEventProcessorApplyMixin:
    """Apply state events to room objects."""

    def _apply_room_state_event(self, room, event_data: dict) -> None:
        event_type = event_data.get("type", "")
        if not _is_room_state_event_type(event_type):
            return
        state_key = event_data.get("state_key", "")
        content = event_data.get("content", {}) or {}

        room.state_events.setdefault(event_type, {})[state_key] = content

        if event_type == M_ROOM_NAME:
            room.display_name = content.get("name", "") or ""
        elif event_type == M_ROOM_TOPIC:
            room.topic, room.topic_html = extract_room_topic(content)
        elif event_type == M_ROOM_AVATAR:
            room.avatar_url = content.get("url") or None
        elif event_type == M_ROOM_JOIN_RULES:
            room.join_rules = content
        elif event_type == M_ROOM_POWER_LEVELS:
            room.power_levels = content
        elif event_type == M_ROOM_HISTORY_VISIBILITY:
            room.history_visibility = content.get("history_visibility")
        elif event_type == M_ROOM_GUEST_ACCESS:
            room.guest_access = content.get("guest_access")
        elif event_type == M_ROOM_CANONICAL_ALIAS:
            room.canonical_alias = content.get("alias")
            alt_aliases = content.get("alt_aliases") or []
            if isinstance(alt_aliases, list):
                room.room_aliases = alt_aliases
        elif event_type == M_ROOM_ALIASES:
            aliases = content.get("aliases") or []
            if isinstance(aliases, list):
                room.room_aliases = aliases
        elif event_type == M_ROOM_ENCRYPTION:
            room.encryption = content
        elif event_type == M_ROOM_CREATE:
            room.create = content
        elif event_type == M_ROOM_TOMBSTONE:
            room.tombstone = content
        elif event_type == M_ROOM_PINNED_EVENTS:
            pinned = content.get("pinned") or []
            if isinstance(pinned, list):
                room.pinned_events = pinned
        elif event_type == M_SPACE_CHILD:
            if content:
                room.space_children[state_key] = content
            else:
                room.space_children.pop(state_key, None)
        elif event_type == M_SPACE_PARENT:
            if content:
                room.space_parents[state_key] = content
            else:
                room.space_parents.pop(state_key, None)
        elif event_type == M_ROOM_THIRD_PARTY_INVITE:
            if content:
                room.third_party_invites[state_key] = content
            else:
                room.third_party_invites.pop(state_key, None)
        elif event_type in LIVE_MESSAGING_STATE_EVENT_TYPES:
            # Receiving either stable or unstable policy state through /sync
            # satisfies the active probe. Prefer the stable event when both are
            # present, otherwise use the current MSC4357 unstable identifier.
            room.live_messaging_policy_probed = True
            resolved = None
            for candidate_type in (
                M_ROOM_LIVE_MESSAGING,
                MSC4357_LIVE_MESSAGING_STATE,
            ):
                candidate = (
                    room.state_events.get(candidate_type, {}).get("", {}) or {}
                )
                enabled = (
                    candidate.get("enabled")
                    if isinstance(candidate, dict)
                    else None
                )
                if isinstance(enabled, bool):
                    resolved = enabled
                    break
            # MSC4357 defines ``enabled`` as a JSON boolean. Invalid or absent
            # values behave like no room-level override (default enabled).
            room.live_messaging_enabled = resolved
