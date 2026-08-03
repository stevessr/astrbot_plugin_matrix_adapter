"""Matrix public-room listing and visibility operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomPublicDirectoryMixin:
    """List public rooms and manage room directory visibility."""

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

    async def get_room_visibility(self, room_id: str) -> dict[str, Any]:
        """
        Get a room's visibility in the public directory

        Args:
            room_id: Room ID

        Returns:
            Response with visibility
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/directory/list/room/{room}"
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
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/directory/list/room/{room}"
        return await self._request("PUT", endpoint, data={"visibility": visibility})
