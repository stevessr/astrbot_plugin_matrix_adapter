"""Room membership lookup and role-list operations."""

from typing import Any

from astrbot.api import logger

from ...path_utils import quote_path_segment


class UserMembersMixin:
    """Membership lookup and administrator/moderator list helpers."""

    async def get_room_member(
        self, room_id: str, user_id: str
    ) -> dict[str, Any] | None:
        """
        Get membership info for a specific user in a room

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Member state event content or None if not found
        """
        room = quote_path_segment(room_id)
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/m.room.member/{user}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            return None

    async def get_room_admins(self, room_id: str) -> list[str]:
        """
        Get list of admin user IDs in a room

        Args:
            room_id: Room ID

        Returns:
            List of admin user IDs (power level >= 100)
        """
        try:
            power_levels = await self.get_power_levels(room_id)
            users = power_levels.get("users", {})
            return [uid for uid, level in users.items() if level >= 100]
        except Exception as e:
            logger.debug(f"Failed to get admins for room {room_id}: {e}")
            return []

    async def get_room_moderators(self, room_id: str) -> list[str]:
        """
        Get list of moderator user IDs in a room

        Args:
            room_id: Room ID

        Returns:
            List of moderator user IDs (power level >= 50)
        """
        try:
            power_levels = await self.get_power_levels(room_id)
            users = power_levels.get("users", {})
            return [uid for uid, level in users.items() if level >= 50]
        except Exception as e:
            logger.debug(f"Failed to get moderators for room {room_id}: {e}")
            return []
