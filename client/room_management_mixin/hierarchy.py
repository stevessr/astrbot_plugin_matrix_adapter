"""Matrix room-summary and space-hierarchy operations."""

from typing import Any

from ..path_utils import quote_path_segment


class RoomHierarchyMixin:
    """Query room summaries and the hierarchy beneath a space."""

    async def get_room_summary(
        self,
        room_id_or_alias: str,
        via: list[str] | None = None,
    ) -> dict[str, Any]:
        """Retrieve the Matrix v1.15 stable summary for a room or alias.

        The response is intentionally returned unchanged so v1.15+ optional
        fields such as ``allowed_room_ids``, ``encryption`` and
        ``room_version`` remain available to callers.
        """
        room = quote_path_segment(room_id_or_alias)
        endpoint = f"/_matrix/client/v1/room_summary/{room}"
        params: dict[str, Any] = {}
        if via:
            params["via"] = list(dict.fromkeys(via))
        return await self._request("GET", endpoint, params=params)

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
            Hierarchy response. v1.15+ optional room-summary fields are
            preserved exactly as returned by the homeserver.
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v1/rooms/{room}/hierarchy"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if from_token:
            params["from"] = from_token
        return await self._request("GET", endpoint, params=params)
