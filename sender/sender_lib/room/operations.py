"""Matrix 消息发送组件 - 房间管理 mixin"""

from typing import Any


class SenderRoomOperationsMixin:
    async def create_room(
        self,
        *,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
    ) -> dict:
        """Create a Matrix room."""
        return await self.client.create_room(
            name=name,
            topic=topic,
            invite=invite,
            is_public=is_public,
            preset=preset,
            creation_content=creation_content,
            initial_state=initial_state,
        )

    async def create_dm_room(
        self,
        user_id: str,
        name: str | None = None,
    ) -> dict:
        """Create a Matrix direct-message room and update m.direct when possible."""
        return await self.client.create_dm_room(user_id=user_id, name=name)

    async def get_user_room(self, user_id: str) -> str | None:
        """Find an existing direct-message room for a Matrix user."""
        return await self.client.get_user_room(user_id)

    async def join_room(self, room_id_or_alias: str) -> dict:
        """Join a Matrix room by room ID or alias."""
        return await self.client.join_room(room_id_or_alias)

    async def leave_room(self, room_id: str) -> dict:
        """Leave a Matrix room."""
        return await self.client.leave_room(room_id)

    async def forget_room(self, room_id: str) -> dict:
        """Forget a Matrix room after leaving it."""
        return await self.client.forget_room(room_id)

    async def get_joined_rooms(self) -> list[str]:
        """Get room IDs joined by the current Matrix account."""
        return await self.client.get_joined_rooms()

    async def get_room_members(self, room_id: str) -> dict:
        """Get Matrix room member events."""
        return await self.client.get_room_members(room_id)

    async def get_room_messages(
        self,
        room_id: str,
        *,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict:
        """Paginate Matrix room messages."""
        return await self.client.room_messages(
            room_id=room_id,
            from_token=from_token,
            to_token=to_token,
            direction=direction,
            limit=limit,
        )

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """Get full Matrix room state."""
        return await self.client.get_room_state(room_id)

    async def get_room_state_event(
        self,
        room_id: str,
        event_type: str,
        state_key: str = "",
    ) -> dict:
        """Get a specific Matrix room state event content."""
        return await self.client.get_room_state_event(
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
        )

    async def set_room_state_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        state_key: str = "",
    ) -> dict:
        """Set a generic Matrix room state event."""
        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            state_key=state_key,
        )

    async def get_event(self, room_id: str, event_id: str) -> dict:
        """Fetch one Matrix event from a room."""
        return await self.client.get_event(room_id=room_id, event_id=event_id)

    async def search_messages(
        self,
        search_term: str,
        *,
        keys: list[str] | None = None,
        filter: dict[str, Any] | None = None,
        order_by: str = "recent",
        event_context: dict[str, Any] | None = None,
    ) -> dict:
        """Search Matrix room events by content."""
        return await self.client.search(
            search_term=search_term,
            keys=keys,
            filter=filter,
            order_by=order_by,
            event_context=event_context,
        )

    async def upgrade_room(self, room_id: str, new_version: str) -> dict:
        """Upgrade a Matrix room to a new room version."""
        return await self.client.upgrade_room(room_id=room_id, new_version=new_version)

    async def knock_room(
        self,
        room_id_or_alias: str,
        reason: str | None = None,
    ) -> dict:
        """Knock on a Matrix room that uses knock join rules."""
        return await self.client.knock_room(
            room_id_or_alias=room_id_or_alias,
            reason=reason,
        )

    async def accept_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Accept a Matrix knock request by inviting the user."""
        return await self.client.accept_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def reject_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Reject a Matrix knock request by kicking the knocking user."""
        return await self.client.reject_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def get_room_hierarchy(
        self,
        room_id: str,
        *,
        limit: int | None = None,
        from_token: str | None = None,
    ) -> dict:
        """Get Matrix space/room hierarchy."""
        return await self.client.get_room_hierarchy(
            room_id=room_id,
            limit=limit,
            from_token=from_token,
        )

    async def invite_user(self, room_id: str, user_id: str) -> dict:
        """Invite a Matrix user to a room."""
        return await self.client.invite_user(room_id=room_id, user_id=user_id)

    async def kick_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict:
        """Kick a Matrix user from a room."""
        return await self.client.kick_user(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def ban_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict:
        """Ban a Matrix user from a room."""
        return await self.client.ban_user(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def unban_user(self, room_id: str, user_id: str) -> dict:
        """Unban a Matrix user from a room."""
        return await self.client.unban_user(room_id=room_id, user_id=user_id)

    async def set_user_power_level(
        self, room_id: str, user_id: str, power_level: int
    ) -> dict:
        """Set a user's room power level."""
        return await self.client.set_user_power_level(
            room_id=room_id,
            user_id=user_id,
            power_level=power_level,
        )

    async def promote_to_admin(self, room_id: str, user_id: str) -> dict:
        """Promote a Matrix user to admin (power level 100)."""
        return await self.client.promote_to_admin(room_id=room_id, user_id=user_id)

    async def get_room_admins(self, room_id: str) -> list[str]:
        """Get room admins (power level >= 100)."""
        return await self.client.get_room_admins(room_id)

    async def get_room_moderators(self, room_id: str) -> list[str]:
        """Get room moderators (power level >= 50)."""
        return await self.client.get_room_moderators(room_id)

    async def set_room_name(self, room_id: str, name: str) -> dict:
        """Set the Matrix room name."""
        return await self.client.set_room_name(room_id=room_id, name=name)

    async def set_room_topic(self, room_id: str, topic: str) -> dict:
        """Set the Matrix room topic."""
        return await self.client.set_room_topic(room_id=room_id, topic=topic)

    async def set_room_avatar(self, room_id: str, avatar_url: str) -> dict:
        """Set the Matrix room avatar MXC URL."""
        return await self.client.set_room_avatar(
            room_id=room_id,
            avatar_url=avatar_url,
        )

    async def set_room_join_rules(self, room_id: str, join_rule: str) -> dict:
        """Set Matrix room join rules."""
        return await self.client.set_room_join_rules(
            room_id=room_id,
            join_rule=join_rule,
        )

    async def set_room_history_visibility(
        self, room_id: str, history_visibility: str
    ) -> dict:
        """Set Matrix room history visibility."""
        return await self.client.set_room_history_visibility(
            room_id=room_id,
            history_visibility=history_visibility,
        )

    async def set_room_guest_access(self, room_id: str, guest_access: str) -> dict:
        """Set Matrix room guest access."""
        return await self.client.set_room_guest_access(
            room_id=room_id,
            guest_access=guest_access,
        )

    async def set_room_canonical_alias(
        self,
        room_id: str,
        alias: str | None,
        alt_aliases: list[str] | None = None,
    ) -> dict:
        """Set or clear the Matrix room canonical alias."""
        return await self.client.set_room_canonical_alias(
            room_id=room_id,
            alias=alias,
            alt_aliases=alt_aliases,
        )

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict:
        """Create or update a Matrix room alias."""
        return await self.client.create_room_alias(
            room_alias=room_alias,
            room_id=room_id,
        )

    async def delete_room_alias(self, room_alias: str) -> dict:
        """Delete a Matrix room alias."""
        return await self.client.delete_room_alias(room_alias)

    async def get_room_alias(self, room_alias: str) -> dict:
        """Resolve a Matrix room alias to its room ID and servers."""
        return await self.client.get_room_alias(room_alias)

    async def list_public_rooms(
        self,
        *,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict:
        """List Matrix public rooms, optionally on another server."""
        return await self.client.list_public_rooms(
            server=server,
            limit=limit,
            since=since,
            filter=filter,
        )

    async def get_room_visibility(self, room_id: str) -> dict:
        """Get room visibility in the public directory."""
        return await self.client.get_room_visibility(room_id)

    async def set_room_visibility(self, room_id: str, visibility: str) -> dict:
        """Set room visibility in the public directory."""
        return await self.client.set_room_visibility(
            room_id=room_id,
            visibility=visibility,
        )

    async def get_room_aliases(self, room_id: str) -> dict:
        """Get aliases associated with a Matrix room."""
        return await self.client.get_room_aliases(room_id)

    async def get_pinned_messages(self, room_id: str) -> list[str]:
        """Get pinned Matrix event IDs in a room."""
        return await self.client.get_room_pinned_events(room_id)

    async def set_pinned_messages(self, room_id: str, event_ids) -> dict:
        """Replace pinned Matrix event IDs in a room."""
        return await self.client.set_room_pinned_events(room_id, event_ids)

    async def pin_message(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict:
        """Pin a Matrix event in a room."""
        return await self.client.pin_room_event(
            room_id=room_id,
            event_id=event_id,
            prepend=prepend,
        )

    async def unpin_message(self, room_id: str, event_id: str) -> dict:
        """Unpin a Matrix event in a room."""
        return await self.client.unpin_room_event(room_id=room_id, event_id=event_id)

    async def mark_room_unread(self, room_id: str, unread: bool = True) -> dict:
        """Mark a room as (un)read for this account (MSC2867)."""
        return await self.client.set_room_marked_unread(room_id, unread)
