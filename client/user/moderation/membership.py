"""Room invitation and membership-removal operations."""

from typing import Any

from ...path_utils import quote_path_segment


class UserMembershipMixin:
    """Invitation, kicking, banning, and unbanning helpers."""

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
