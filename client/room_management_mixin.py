"""
Matrix HTTP Client - Room Management Mixin
Provides room lifecycle and hierarchy methods
"""

from typing import Any


class RoomManagementMixin:
    """Room management methods for Matrix client"""

    async def forget_room(self, room_id: str) -> dict[str, Any]:
        """
        Forget a room (after leaving)

        Args:
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/forget"
        return await self._request("POST", endpoint, data={})

    async def upgrade_room(self, room_id: str, new_version: str) -> dict[str, Any]:
        """
        Upgrade a room to a new version

        Args:
            room_id: Room ID
            new_version: New room version (e.g., "10")

        Returns:
            Response with replacement_room
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/upgrade"
        return await self._request("POST", endpoint, data={"new_version": new_version})

    async def knock_room(
        self, room_id_or_alias: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Knock on a room (if supported by server)

        Args:
            room_id_or_alias: Room ID or alias
            reason: Optional reason

        Returns:
            Knock response with room_id
        """
        endpoint = f"/_matrix/client/v3/knock/{room_id_or_alias}"
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def get_room_hierarchy(
        self, room_id: str, limit: int | None = None, from_token: str | None = None
    ) -> dict[str, Any]:
        """
        Get room hierarchy (spaces)

        Args:
            room_id: Room ID
            limit: Optional limit
            from_token: Pagination token

        Returns:
            Hierarchy response
        """
        endpoint = f"/_matrix/client/v1/rooms/{room_id}/hierarchy"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if from_token:
            params["from"] = from_token
        return await self._request("GET", endpoint, params=params)
