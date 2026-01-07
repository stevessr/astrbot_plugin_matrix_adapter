"""
Matrix HTTP Client - Room Directory Mixin
Provides room directory, aliases, and public rooms methods
"""

from typing import Any


class RoomDirectoryMixin:
    """Room directory and aliases methods for Matrix client"""

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict[str, Any]:
        """
        Create or update a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("PUT", endpoint, data={"room_id": room_id})

    async def delete_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Delete a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("DELETE", endpoint)

    async def get_room_alias(self, room_alias: str) -> dict[str, Any]:
        """
        Resolve a room alias

        Args:
            room_alias: Room alias (e.g., #alias:example.com)

        Returns:
            Dict containing room_id and servers
        """
        endpoint = f"/_matrix/client/v3/directory/room/{room_alias}"
        return await self._request("GET", endpoint)

    async def list_public_rooms(
        self,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        List public rooms

        Args:
            server: Optional server to query
            limit: Optional limit
            since: Pagination token
            filter: Optional filter (uses POST when provided)

        Returns:
            Public rooms response
        """
        endpoint = "/_matrix/client/v3/publicRooms"
        params: dict[str, Any] = {}
        if server:
            params["server"] = server
        if limit is not None:
            params["limit"] = limit
        if since:
            params["since"] = since

        if filter is None:
            return await self._request("GET", endpoint, params=params)

        data: dict[str, Any] = {"filter": filter}
        if server:
            data["server"] = server
        if limit is not None:
            data["limit"] = limit
        if since:
            data["since"] = since
        return await self._request("POST", endpoint, data=data)

    async def get_room_aliases(self, room_id: str) -> dict[str, Any]:
        """
        Get aliases for a room

        Args:
            room_id: Room ID

        Returns:
            Response containing aliases
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/aliases"
        return await self._request("GET", endpoint)

    async def get_room_visibility(self, room_id: str) -> dict[str, Any]:
        """
        Get a room's visibility in the public directory

        Args:
            room_id: Room ID

        Returns:
            Response with visibility
        """
        endpoint = f"/_matrix/client/v3/directory/list/room/{room_id}"
        return await self._request("GET", endpoint)

    async def set_room_visibility(
        self, room_id: str, visibility: str
    ) -> dict[str, Any]:
        """
        Set a room's visibility in the public directory

        Args:
            room_id: Room ID
            visibility: "public" or "private"

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/directory/list/room/{room_id}"
        return await self._request("PUT", endpoint, data={"visibility": visibility})
