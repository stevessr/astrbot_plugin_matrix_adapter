"""Core room membership operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomMembershipMixin:
    """Join, leave, and inspect room membership."""

    async def join_room(
        self, room_id: str, server_name: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Join a room

        Args:
            room_id: Room ID or alias
            server_name: Optional list of server names to try joining via
                (MSC3881 remote room joining, e.g. joining a room ID on
                another homeserver). Also accepted as ``via`` servers.

        Returns:
            Join response with room_id
        """
        data: dict[str, Any] = {}
        if server_name:
            data["server_name"] = list(server_name)
        endpoint = f"/_matrix/client/v3/join/{quote_path_segment(room_id)}"
        return await self._request("POST", endpoint, data=data)

    async def leave_room(self, room_id: str) -> dict[str, Any]:
        """
        Leave a room

        Args:
            room_id: Room ID

        Returns:
            Leave response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/leave"
        return await self._request("POST", endpoint, data={})

    async def get_room_members(self, room_id: str) -> dict[str, Any]:
        """
        Get room members

        Args:
            room_id: Room ID

        Returns:
            Room members data
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/members"
        return await self._request("GET", endpoint)


__all__ = ["RoomMembershipMixin"]
