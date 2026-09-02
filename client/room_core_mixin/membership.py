"""Core room membership operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomMembershipMixin:
    """Join, leave, and inspect room membership."""

    async def join_room(
        self,
        room_id: str,
        server_name: list[str] | None = None,
        *,
        via: list[str] | None = None,
    ) -> dict[str, Any]:
        """Join a room using the current stable ``via`` query parameter.

        ``server_name`` is retained as a source-compatible alias for callers
        written against the pre-v1.14 adapter API. It is never emitted on the
        wire: Matrix v1.14 removed the old ``server_name`` parameter after
        ``via`` replaced it in v1.12.
        """
        selected_via = via if via is not None else server_name
        params: dict[str, Any] = {}
        if selected_via:
            params["via"] = list(dict.fromkeys(selected_via))
        endpoint = f"/_matrix/client/v3/join/{quote_path_segment(room_id)}"
        return await self._request("POST", endpoint, data={}, params=params)

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
