"""Room state persistence and in-memory application handlers."""

import asyncio

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


class MatrixEventProcessorPersistenceMixin:
    """Persist room state and apply state events to room objects."""

    async def _persist_room_state(self, room) -> None:
        """将房间状态/成员数据持久化到存储后端。"""
        await asyncio.to_thread(
            self.room_member_store.upsert,
            room_id=room.room_id,
            members=room.members,
            member_avatars=room.member_avatars,
            member_count=room.member_count,
            is_direct=room.is_direct,
            room_name=room.display_name,
            topic=room.topic,
            avatar_url=room.avatar_url,
            join_rules=room.join_rules,
            power_levels=room.power_levels,
            history_visibility=room.history_visibility,
            guest_access=room.guest_access,
            canonical_alias=room.canonical_alias,
            room_aliases=room.room_aliases,
            encryption=room.encryption,
            create=room.create,
            tombstone=room.tombstone,
            pinned_events=room.pinned_events,
            space_children=room.space_children,
            space_parents=room.space_parents,
            third_party_invites=room.third_party_invites,
            state_events=room.state_events,
        )

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
            room.topic = content.get("topic", "") or ""
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
            enabled = content.get("enabled")
            if isinstance(enabled, bool):
                room.live_messaging_enabled = enabled
            else:
                # MSC4357 defines ``enabled`` as a JSON boolean. Invalid or
                # absent values behave like no usable room-level override.
                room.live_messaging_enabled = None
