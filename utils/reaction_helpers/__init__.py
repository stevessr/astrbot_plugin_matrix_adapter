"""Composable helpers for Matrix reaction targeting."""

from .events import event_origin_server_ts_ms, extract_matrix_event_text
from .keys import normalize_shortcode_token, resolve_reaction_key
from .registry import (
    ReactionKeyResolver,
    clear_reaction_key_resolvers,
    list_reaction_key_resolvers,
    register_reaction_key_resolver,
    unregister_reaction_key_resolver,
)
from .search import (
    collect_room_message_events,
    default_anchor_time_ms,
    find_room_event_for_reaction,
    select_nearest_matching_event,
)
from .time import parse_reaction_anchor_time_ms

__all__ = [
    "ReactionKeyResolver",
    "clear_reaction_key_resolvers",
    "collect_room_message_events",
    "default_anchor_time_ms",
    "event_origin_server_ts_ms",
    "extract_matrix_event_text",
    "find_room_event_for_reaction",
    "list_reaction_key_resolvers",
    "normalize_shortcode_token",
    "parse_reaction_anchor_time_ms",
    "register_reaction_key_resolver",
    "resolve_reaction_key",
    "select_nearest_matching_event",
    "unregister_reaction_key_resolver",
]
