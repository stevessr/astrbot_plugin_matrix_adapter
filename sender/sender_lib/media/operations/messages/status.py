"""Reaction, receipt, and typing methods."""


class SenderMediaStatusMixin:
    """Send reactions, receipts, and typing indicators."""

    async def send_reaction(self, room_id: str, event_id: str, emoji: str) -> dict:
        """Send a reaction to a message in a room."""
        return await self.client.send_reaction(room_id, event_id, emoji)

    async def send_receipt(
        self,
        room_id: str,
        event_id: str,
        receipt_type: str = "m.read",
        thread_id: str | None = None,
    ) -> dict:
        """Send a read/private-read receipt for a room event."""
        if receipt_type == "m.read.private":
            return await self.client.send_read_receipt_private(
                room_id, event_id, thread_id=thread_id
            )
        return await self.client.send_read_receipt(
            room_id, event_id, thread_id=thread_id
        )

    async def set_typing(
        self, room_id: str, typing: bool, timeout_ms: int = 30000
    ) -> dict:
        """Update typing indicator state."""
        return await self.client.set_typing(
            room_id=room_id, typing=typing, timeout=timeout_ms
        )
