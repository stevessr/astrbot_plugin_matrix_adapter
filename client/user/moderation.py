"""Room membership and permission operations for Matrix users."""

from typing import Any

from astrbot.api import logger

from ..path_utils import quote_path_segment


class UserModerationMixin:
    """Invitation, moderation, power-level, and member helpers."""

    async def invite_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Invite a user to a room

        Args:
            room_id: Room ID
            user_id: User ID to invite

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/invite"
        return await self._request("POST", endpoint, data={"user_id": user_id})

    # ========== User Removal ==========

    async def kick_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Kick a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to kick
            reason: Optional reason for kicking

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/kick"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def ban_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Ban a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to ban
            reason: Optional reason for banning

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/ban"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def unban_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Unban a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to unban

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/unban"
        return await self._request("POST", endpoint, data={"user_id": user_id})

    # ========== Power Levels (Permissions) ==========

    async def get_power_levels(self, room_id: str) -> dict[str, Any]:
        """
        Get power levels for a room

        Args:
            room_id: Room ID

        Returns:
            Power levels state event content
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/m.room.power_levels/"
        return await self._request("GET", endpoint)

    async def set_power_levels(
        self, room_id: str, power_levels: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set power levels for a room

        Args:
            room_id: Room ID
            power_levels: Power levels content

        Returns:
            Response with event_id
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/m.room.power_levels/"
        return await self._request("PUT", endpoint, data=power_levels)

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
