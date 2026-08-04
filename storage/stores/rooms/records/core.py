"""Room member record upsert orchestration."""

import time
from typing import Any

from astrbot.api import logger


class MatrixRoomMemberRecordsCoreMixin:
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

        existing = self.get(room_id)
        updated = False

        # If no existing data, this is a new entry
        if not existing:
            existing = {"room_id": room_id}
            updated = True
        else:
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

            try:
                self._store.upsert(room_id, existing)
                self._cache[room_id] = existing
                self._cache.move_to_end(room_id, last=True)
                while len(self._cache) > self._MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)
                logger.info(f"已保存房间成员数据：{room_id} ({member_count} 个成员)")
            except Exception as e:
                logger.error(f"保存房间成员数据失败 {room_id}: {e}")
