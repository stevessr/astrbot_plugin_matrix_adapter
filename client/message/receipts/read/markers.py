"""Matrix read marker operations."""

from typing import Any

from .....constants import MSC4446_ALLOW_BACKWARD
from ....path_utils import quote_path_segment


class MessageReadMarkersMixin:
    """Set read markers for a room."""

    async def send_read_markers(
        self,
        room_id: str,
        fully_read: str | None = None,
        read: str | None = None,
        allow_backward: bool = False,
    ) -> dict[str, Any]:
        """
        Set read markers for a room

        Args:
            room_id: Room ID
            fully_read: Event ID for fully_read marker
            read: Event ID for read marker
            allow_backward: MSC4446 — allow moving ``m.fully_read`` back to an earlier
                event. Writes both the stable key ``allow_backward`` and the unstable
                key ``com.beeper.allow_backward`` for servers that haven't adopted the
                stable name yet.
                Note: read receipts (``m.read`` / ``m.read.private``) remain monotonic.

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/read_markers"
        data: dict[str, Any] = {}
        if fully_read:
            data["m.fully_read"] = fully_read
        if read:
            data["m.read"] = read
        if allow_backward:
            data["allow_backward"] = True
            data[MSC4446_ALLOW_BACKWARD] = True
        return await self._request("POST", endpoint, data=data)

    async def send_fully_read_receipt(
        self,
        room_id: str,
        event_id: str,
        *,
        allow_backward: bool = False,
    ) -> dict[str, Any]:
        """
        Set the fully read marker to a specific event via the receipt endpoint
        (MSC4446 aware).

        Uses ``POST /_matrix/client/v3/rooms/{roomId}/receipt/m.fully_read/{eventId}``,
        writing both stable and unstable keys when ``allow_backward=True`` to allow
        moving the marker back to an earlier event. This endpoint only accepts
        ``m.fully_read`` receipt type; other types are rejected with 400.

        Args:
            room_id: Room ID
            event_id: Event ID to mark as fully read
            allow_backward: Allow moving the marker to an earlier event

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/receipt/m.fully_read/{event}"
        data: dict[str, Any] = {}
        if allow_backward:
            data["allow_backward"] = True
            data[MSC4446_ALLOW_BACKWARD] = True
        return await self._request("POST", endpoint, data=data)


__all__ = ["MessageReadMarkersMixin"]
