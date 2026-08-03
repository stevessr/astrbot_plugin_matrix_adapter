"""Room membership and power-level moderation operations."""


class SenderRoomModerationMixin:
    """Delegates room membership and moderation operations."""

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
