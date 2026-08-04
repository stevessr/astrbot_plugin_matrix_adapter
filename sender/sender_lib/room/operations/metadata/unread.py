"""Room unread-marker delegation operations."""


class SenderRoomUnreadMixin:
    """Delegate room unread-marker operations to the client."""

    async def mark_room_unread(self, room_id: str, unread: bool = True) -> dict:
        """Mark a room as (un)read for this account (MSC2867)."""
        return await self.client.set_room_marked_unread(room_id, unread)
