"""Room member record merge field groups."""

# Fields merged whenever the incoming value differs from the stored one.
_MERGE_ALWAYS_FIELDS = (
    "members",
    "member_avatars",
    "member_count",
)

# Fields merged only when the incoming value is explicitly provided.
_MERGE_IF_NOT_NONE_FIELDS = (
    "is_direct",
    "room_name",
    "topic",
    "avatar_url",
    "join_rules",
    "power_levels",
    "history_visibility",
    "guest_access",
    "canonical_alias",
    "room_aliases",
    "encryption",
    "create",
    "tombstone",
    "pinned_events",
    "space_children",
    "space_parents",
    "third_party_invites",
    "state_events",
)
