"""Room state inspection and initial-sync operations."""

import json
from typing import Any

from ...constants import MEMBERSHIP_INVITE, MEMBERSHIP_JOIN, MEMBERSHIP_LEAVE
from ..path_utils import quote_path_segment


class RoomStateInspectionMixin:
    """Read-only room state and timeline inspection helpers."""

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

    async def initial_sync(
        self, room_id: str, limit: int | None = None, archived: bool | None = None
    ) -> dict[str, Any]:
        """
        Get room initial sync via /sync with a room filter.

        Args:
            room_id: Room ID
            limit: Optional timeline limit
            archived: Ignored (not supported by /sync)

        Returns:
            Room data from /sync (join/invite/leave), or empty dict if missing.
        """
        filter_data: dict[str, Any] = {"room": {"rooms": [room_id]}}
        if limit is not None:
            filter_data["room"]["timeline"] = {"limit": limit}

        params: dict[str, Any] = {
            "filter": json.dumps(filter_data, ensure_ascii=True),
            "full_state": True,
        }
        response = await self._request("GET", "/_matrix/client/v3/sync", params=params)

        rooms = response.get("rooms", {})
        for bucket in (MEMBERSHIP_JOIN, MEMBERSHIP_INVITE, MEMBERSHIP_LEAVE):
            room_bucket = rooms.get(bucket, {})
            if room_id in room_bucket:
                return room_bucket[room_id]
        return {}
