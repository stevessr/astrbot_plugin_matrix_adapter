"""Matrix room membership event dispatch and shared persistence."""

import asyncio

from astrbot.api import logger

from .....constants import (
    MEMBERSHIP_BAN,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    MEMBERSHIP_KNOCK,
    MEMBERSHIP_LEAVE,
)


class MatrixEventProcessorMembershipCoreMixin:
    """Dispatch membership transitions and persist room snapshots."""

    async def _handle_member_event(self, room, event_data: dict):
        """Handle m.room.member changes and persist profile updates."""
        user_id = event_data.get("state_key")
        if not user_id:
            return
        e2ee_manager = getattr(self, "e2ee_manager", None)
        content = event_data.get("content", {})
        membership = content.get("membership")
        display_name = content.get("displayname") or room.members.get(user_id, user_id)
        avatar_url = content.get("avatar_url") or room.member_avatars.get(user_id)
        rotated_for_limited_gap = False
        if (
            e2ee_manager
            and getattr(room, "timeline_limited", False)
            and membership != MEMBERSHIP_JOIN
            and user_id != self.user_id
        ):
            # A non-join membership event after a limited timeline may hide an
            # intervening join/leave. Matrix v1.19 requires session rotation.
            try:
                await e2ee_manager.on_room_member_left(room.room_id, user_id)
                rotated_for_limited_gap = True
            except Exception as e:
                logger.debug(f"Limited-sync Megolm rotation failed: {e}")

        if membership == MEMBERSHIP_JOIN:
            await self._handle_member_join(
                room, user_id, display_name, avatar_url, e2ee_manager
            )
        elif membership == MEMBERSHIP_INVITE:
            await self._handle_member_invite(
                room, user_id, display_name, avatar_url, e2ee_manager
            )
        elif membership == MEMBERSHIP_KNOCK:
            await self._handle_member_knock(room, user_id, display_name, avatar_url)
        elif membership in (MEMBERSHIP_LEAVE, MEMBERSHIP_BAN):
            await self._handle_member_leave(
                room, user_id, display_name, e2ee_manager, rotated_for_limited_gap
            )
        else:
            # Membership changes without join/leave still update profile fields if present.
            if content.get("displayname") or content.get("avatar_url"):
                room.members[user_id] = display_name
                if avatar_url:
                    room.member_avatars[user_id] = avatar_url
                await asyncio.to_thread(
                    self.user_store.upsert, user_id, display_name, avatar_url
                )
                await self._persist_room_member_state(room)

    async def _persist_room_member_state(self, room):
        """Persist the current room member snapshot to storage."""
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
