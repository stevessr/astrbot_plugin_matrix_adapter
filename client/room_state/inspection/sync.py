"""Room initial-sync via /sync with a room filter."""

import json
from typing import Any

from ....constants import MEMBERSHIP_INVITE, MEMBERSHIP_JOIN, MEMBERSHIP_LEAVE


class RoomStateInspectionSyncMixin:
    """Fetch room data from the /sync endpoint."""

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


__all__ = ["RoomStateInspectionSyncMixin"]
