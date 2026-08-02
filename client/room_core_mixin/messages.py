"""Room message history operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomMessageHistoryMixin:
    """Read room timelines and joined-room listings."""

    async def room_messages(
        self,
        room_id: str,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict[str, Any]:
        """
        Get messages from a room

        Args:
            room_id: Room ID
            from_token: Token to start from
            to_token: Token to end at
            direction: Direction to paginate ('b' for backwards, 'f' for forwards)
            limit: Maximum number of events to return

        Returns:
            Response with chunk of events and pagination tokens
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/messages"
        params = {
            "dir": direction,
            "limit": limit,
        }
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token

        return await self._request("GET", endpoint, params=params)

    async def get_joined_rooms(self) -> list[str]:
        """
        Get list of joined room IDs

        Returns:
            List of room IDs
        """
        response = await self._request("GET", "/_matrix/client/v3/joined_rooms")
        return response.get("joined_rooms", [])


__all__ = ["RoomMessageHistoryMixin"]
