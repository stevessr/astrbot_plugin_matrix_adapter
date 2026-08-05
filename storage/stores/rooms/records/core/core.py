"""Room member record upsert orchestration."""

from typing import Any

from .fields import MatrixRoomMemberRecordsFieldsMixin
from .lookup import MatrixRoomMemberRecordsLookupMixin
from .persist import MatrixRoomMemberRecordsPersistMixin


class MatrixRoomMemberRecordsUpsertMixin(
    MatrixRoomMemberRecordsFieldsMixin,
    MatrixRoomMemberRecordsLookupMixin,
    MatrixRoomMemberRecordsPersistMixin,
):
    """Persist room member records through a guarded upsert flow."""

    def upsert(
        self,
        room_id: str,
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
    ):
        """
        Save or update room member data.

        Args:
            room_id: Room ID
            members: Dictionary mapping user_id to display_name
            member_avatars: Dictionary mapping user_id to avatar URL
            member_count: Total number of members
            is_direct: Whether this is a direct message room
        """
        if not room_id:
            return

        existing, updated = self._load_existing_record(room_id)

        if not updated:
            # Check if data has changed
            updated = self._merge_room_record_diff(
                existing,
                members=members,
                member_avatars=member_avatars,
                member_count=member_count,
                is_direct=is_direct,
                room_name=room_name,
                topic=topic,
                avatar_url=avatar_url,
                join_rules=join_rules,
                power_levels=power_levels,
                history_visibility=history_visibility,
                guest_access=guest_access,
                canonical_alias=canonical_alias,
                room_aliases=room_aliases,
                encryption=encryption,
                create=create,
                tombstone=tombstone,
                pinned_events=pinned_events,
                space_children=space_children,
                space_parents=space_parents,
                third_party_invites=third_party_invites,
                state_events=state_events,
            )

        # Always update the data if it's a new entry or changed
        if updated:
            existing = self._apply_record_fields(
                existing,
                members=members,
                member_avatars=member_avatars,
                member_count=member_count,
                is_direct=is_direct,
                room_name=room_name,
                topic=topic,
                avatar_url=avatar_url,
                join_rules=join_rules,
                power_levels=power_levels,
                history_visibility=history_visibility,
                guest_access=guest_access,
                canonical_alias=canonical_alias,
                room_aliases=room_aliases,
                encryption=encryption,
                create=create,
                tombstone=tombstone,
                pinned_events=pinned_events,
                space_children=space_children,
                space_parents=space_parents,
                third_party_invites=third_party_invites,
                state_events=state_events,
            )
            self._persist_record(room_id, existing, member_count)
