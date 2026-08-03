"""Room creation, membership lifecycle, and knock operations."""

from typing import Any


class SenderRoomLifecycleMixin:
    """Delegates room creation, membership lifecycle, and knock operations."""

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
