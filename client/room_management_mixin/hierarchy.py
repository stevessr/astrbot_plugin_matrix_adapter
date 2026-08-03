"""Matrix space room-hierarchy operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomHierarchyMixin:
    """Query the hierarchy of rooms beneath a space."""

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
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v1/rooms/{room}/hierarchy"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if from_token:
            params["from"] = from_token
        return await self._request("GET", endpoint, params=params)
