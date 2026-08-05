"""Room forgetting and upgrade operations."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomTransitionMixin:
    """Manage room lifecycle transitions."""

    async def forget_room(self, room_id: str) -> dict[str, Any]:
        """
        Forget a room (after leaving)

        Args:
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/forget"
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
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/upgrade"
        return await self._request("POST", endpoint, data={"new_version": new_version})


__all__ = ["RoomTransitionMixin"]
