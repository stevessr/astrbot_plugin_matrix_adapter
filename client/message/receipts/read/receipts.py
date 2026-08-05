"""Matrix read receipt operations."""

from typing import Any

from ....path_utils import quote_path_segment


class MessageReadReceiptsMixin:
    """Send per-event read receipts."""

    async def send_read_receipt(
        self, room_id: str, event_id: str, thread_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge
            thread_id: Optional thread ID for per-thread receipts (MSC3771)

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}"
        data: dict[str, Any] = {}
        if thread_id:
            data["thread_id"] = thread_id
        return await self._request("POST", endpoint, data=data)

    async def send_read_receipt_private(
        self, room_id: str, event_id: str, thread_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send private read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge
            thread_id: Optional thread ID for per-thread receipts (MSC3771)

        Returns:
            Response data
        """
        endpoint = (
            f"/_matrix/client/v3/rooms/{quote_path_segment(room_id)}"
            f"/receipt/m.read.private/{quote_path_segment(event_id)}"
        )
        data: dict[str, Any] = {}
        if thread_id:
            data["thread_id"] = thread_id
        return await self._request("POST", endpoint, data=data)


__all__ = ["MessageReadReceiptsMixin"]
