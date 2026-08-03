"""Composable room metadata and access-policy handlers."""

from astrbot.api.message_components import Plain

from ..common import _format_limited_list
from .aliases import (
    handle_room_aliases,
    handle_room_canonical_alias,
    handle_room_pinned_events,
    handle_room_third_party_invite,
)
from .basic import (
    handle_room_avatar_change,
    handle_room_create,
    handle_room_encryption,
    handle_room_name_change,
    handle_room_tombstone,
    handle_room_topic_change,
)
from .policy import (
    handle_room_guest_access,
    handle_room_history_visibility,
    handle_room_join_rules,
    handle_room_power_levels,
    handle_room_server_acl,
)

__all__ = [
    "Plain",
    "_format_limited_list",
    "handle_room_aliases",
    "handle_room_avatar_change",
    "handle_room_canonical_alias",
    "handle_room_create",
    "handle_room_encryption",
    "handle_room_guest_access",
    "handle_room_history_visibility",
    "handle_room_join_rules",
    "handle_room_name_change",
    "handle_room_pinned_events",
    "handle_room_power_levels",
    "handle_room_server_acl",
    "handle_room_third_party_invite",
    "handle_room_tombstone",
    "handle_room_topic_change",
]
