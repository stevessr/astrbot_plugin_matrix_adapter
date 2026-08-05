"""Simple room inspection endpoints."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomStateInspectionEndpointMixin:
    """Read-only room state endpoint helpers."""

    async def get_joined_members(self, room_id: str) -> dict[str, Any]:
        """
        Get joined members in a room

        Args:
            room_id: Room ID

        Returns:
            Joined members response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/joined_members"
        return await self._request("GET", endpoint)

    async def get_room_state_ids(self, room_id: str) -> dict[str, Any]:
        """
        Get state event IDs for a room

        Args:
            room_id: Room ID

        Returns:
            State IDs response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state_ids"
        return await self._request("GET", endpoint)

    async def get_room_summary(self, room_id: str) -> dict[str, Any]:
        """
        Get room summary

        Args:
            room_id: Room ID

        Returns:
            Summary response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/summary"
        return await self._request("GET", endpoint)

    async def timestamp_to_event(
        self, room_id: str, timestamp: int, direction: str = "b"
    ) -> dict[str, Any]:
        """
        Find the event at or near a timestamp

        Args:
            room_id: Room ID
            timestamp: Timestamp in milliseconds
            direction: "b" or "f"

        Returns:
            Event lookup response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/timestamp_to_event"
        params = {"ts": timestamp, "dir": direction}
        return await self._request("GET", endpoint, params=params)


__all__ = ["RoomStateInspectionEndpointMixin"]
