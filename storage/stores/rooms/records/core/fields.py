"""Record field application for upserts."""

import time
from typing import Any


class MatrixRoomMemberRecordsFieldsMixin:
    """Apply updated fields onto a room member record."""

    def _apply_record_fields(
        self,
        existing: dict,
        members: dict[str, str],
        member_avatars: dict[str, str],
        member_count: int,
        is_direct: bool | None = None,
        room_name: str | None = None,
        topic: str | None = None,
        avatar_url: str | None = None,
        join_rules: dict[str, Any] | None = None,
        power_levels: dict[str, Any] | None = None,
        history_visibility: str | None = None,
        guest_access: str | None = None,
        canonical_alias: str | None = None,
        room_aliases: list[str] | None = None,
        encryption: dict[str, Any] | None = None,
        create: dict[str, Any] | None = None,
        tombstone: dict[str, Any] | None = None,
        pinned_events: list[str] | None = None,
        space_children: dict[str, dict[str, Any]] | None = None,
        space_parents: dict[str, dict[str, Any]] | None = None,
        third_party_invites: dict[str, dict[str, Any]] | None = None,
        state_events: dict[str, dict[str, Any]] | None = None,
    ) -> dict:
        existing["members"] = members
        existing["member_avatars"] = member_avatars
        existing["member_count"] = member_count
        if is_direct is not None:
            existing["is_direct"] = is_direct
        if room_name is not None:
            existing["room_name"] = room_name
        if topic is not None:
            existing["topic"] = topic
        if avatar_url is not None:
            existing["avatar_url"] = avatar_url
        if join_rules is not None:
            existing["join_rules"] = join_rules
        if power_levels is not None:
            existing["power_levels"] = power_levels
        if history_visibility is not None:
            existing["history_visibility"] = history_visibility
        if guest_access is not None:
            existing["guest_access"] = guest_access
        if canonical_alias is not None:
            existing["canonical_alias"] = canonical_alias
        if room_aliases is not None:
            existing["room_aliases"] = room_aliases
        if encryption is not None:
            existing["encryption"] = encryption
        if create is not None:
            existing["create"] = create
        if tombstone is not None:
            existing["tombstone"] = tombstone
        if pinned_events is not None:
            existing["pinned_events"] = pinned_events
        if space_children is not None:
            existing["space_children"] = space_children
        if space_parents is not None:
            existing["space_parents"] = space_parents
        if third_party_invites is not None:
            existing["third_party_invites"] = third_party_invites
        if state_events is not None:
            existing["state_events"] = state_events
        existing["updated_at"] = int(time.time())
        return existing
