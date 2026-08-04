"""Room member record field-diff merge logic."""


class MatrixRoomMemberRecordsDiffMixin:
    """Compare incoming member fields against an existing record."""

    def _merge_room_record_diff(self, existing: dict, **kwargs) -> bool:
        """Apply any changed fields to ``existing``.

        Returns True when at least one field changed.
        """
        updated = False

        if kwargs.get("members") != existing.get("members"):
            existing["members"] = kwargs.get("members")
            updated = True

        if kwargs.get("member_avatars") != existing.get("member_avatars"):
            existing["member_avatars"] = kwargs.get("member_avatars")
            updated = True

        if kwargs.get("member_count") != existing.get("member_count"):
            existing["member_count"] = kwargs.get("member_count")
            updated = True

        is_direct = kwargs.get("is_direct")
        if is_direct is not None and is_direct != existing.get("is_direct"):
            existing["is_direct"] = is_direct
            updated = True

        room_name = kwargs.get("room_name")
        if room_name is not None and room_name != existing.get("room_name"):
            existing["room_name"] = room_name
            updated = True

        topic = kwargs.get("topic")
        if topic is not None and topic != existing.get("topic"):
            existing["topic"] = topic
            updated = True

        avatar_url = kwargs.get("avatar_url")
        if avatar_url is not None and avatar_url != existing.get("avatar_url"):
            existing["avatar_url"] = avatar_url
            updated = True

        join_rules = kwargs.get("join_rules")
        if join_rules is not None and join_rules != existing.get("join_rules"):
            existing["join_rules"] = join_rules
            updated = True

        power_levels = kwargs.get("power_levels")
        if power_levels is not None and power_levels != existing.get("power_levels"):
            existing["power_levels"] = power_levels
            updated = True

        history_visibility = kwargs.get("history_visibility")
        if history_visibility is not None and history_visibility != existing.get(
            "history_visibility"
        ):
            existing["history_visibility"] = history_visibility
            updated = True

        guest_access = kwargs.get("guest_access")
        if guest_access is not None and guest_access != existing.get("guest_access"):
            existing["guest_access"] = guest_access
            updated = True

        canonical_alias = kwargs.get("canonical_alias")
        if canonical_alias is not None and canonical_alias != existing.get(
            "canonical_alias"
        ):
            existing["canonical_alias"] = canonical_alias
            updated = True

        room_aliases = kwargs.get("room_aliases")
        if room_aliases is not None and room_aliases != existing.get("room_aliases"):
            existing["room_aliases"] = room_aliases
            updated = True

        encryption = kwargs.get("encryption")
        if encryption is not None and encryption != existing.get("encryption"):
            existing["encryption"] = encryption
            updated = True

        create = kwargs.get("create")
        if create is not None and create != existing.get("create"):
            existing["create"] = create
            updated = True

        tombstone = kwargs.get("tombstone")
        if tombstone is not None and tombstone != existing.get("tombstone"):
            existing["tombstone"] = tombstone
            updated = True

        pinned_events = kwargs.get("pinned_events")
        if pinned_events is not None and pinned_events != existing.get("pinned_events"):
            existing["pinned_events"] = pinned_events
            updated = True

        space_children = kwargs.get("space_children")
        if space_children is not None and space_children != existing.get(
            "space_children"
        ):
            existing["space_children"] = space_children
            updated = True

        space_parents = kwargs.get("space_parents")
        if space_parents is not None and space_parents != existing.get("space_parents"):
            existing["space_parents"] = space_parents
            updated = True

        third_party_invites = kwargs.get("third_party_invites")
        if third_party_invites is not None and third_party_invites != existing.get(
            "third_party_invites"
        ):
            existing["third_party_invites"] = third_party_invites
            updated = True

        state_events = kwargs.get("state_events")
        if state_events is not None and state_events != existing.get("state_events"):
            existing["state_events"] = state_events
            updated = True

        return updated
