"""Per-user power-level and role helpers."""

from typing import Any


class UserPowerLevelRoleMixin:
    """Update individual user power levels."""

    async def set_user_power_level(
        self, room_id: str, user_id: str, power_level: int
    ) -> dict[str, Any]:
        """
        Set power level for a specific user in a room

        Args:
            room_id: Room ID
            user_id: User ID
            power_level: Power level (0=default, 50=moderator, 100=admin)

        Returns:
            Response with event_id
        """
        # Get current power levels
        current = await self.get_power_levels(room_id)

        # Update user's power level
        if "users" not in current:
            current["users"] = {}
        current["users"][user_id] = power_level

        return await self.set_power_levels(room_id, current)

    async def promote_to_moderator(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Promote a user to moderator (power level 50)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 50)

    async def promote_to_admin(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Promote a user to admin (power level 100)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 100)

    async def demote_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Demote a user to default power level (0)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 0)


__all__ = ["UserPowerLevelRoleMixin"]
