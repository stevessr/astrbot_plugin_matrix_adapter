"""Simple room inspection endpoints."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomStateInspectionEndpointMixin:
    """Read-only room state endpoint helpers."""

    async def get_joined_members(self, room_id: str) -> dict[str, Any]:
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/joined_members"
        return await self._request("GET", endpoint)

    async def get_room_state_ids(self, room_id: str) -> dict[str, Any]:
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state_ids"
        return await self._request("GET", endpoint)

    async def get_room_summary(self, room_id: str) -> dict[str, Any]:
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/summary"
        return await self._request("GET", endpoint)

    async def timestamp_to_event(
        self, room_id: str, timestamp: int, direction: str = "b"
    ) -> dict[str, Any]:
        """Find the closest room event before/after a millisecond timestamp.

        Matrix v1.6 / MSC3030 accepts ``dir=b`` (at or before) and ``dir=f``
        (at or after). Reject malformed local input instead of emitting a wire
        request the homeserver can only answer with ``M_INVALID_PARAM``.
        """
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise ValueError("timestamp must be a non-negative integer in milliseconds")
        if direction not in {"b", "f"}:
            raise ValueError("direction must be 'b' or 'f'")

        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/timestamp_to_event"
        return await self._request(
            "GET", endpoint, params={"ts": timestamp, "dir": direction}
        )


__all__ = ["RoomStateInspectionEndpointMixin"]
