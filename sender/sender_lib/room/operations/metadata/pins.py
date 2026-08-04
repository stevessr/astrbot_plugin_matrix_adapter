"""Room pinned-message delegation operations."""


class SenderRoomPinsMixin:
    """Delegate room pinned-message operations to the client."""

    async def get_pinned_messages(self, room_id: str) -> list[str]:
        """Get pinned Matrix event IDs in a room."""
        return await self.client.get_room_pinned_events(room_id)

    async def set_pinned_messages(self, room_id: str, event_ids) -> dict:
        """Replace pinned Matrix event IDs in a room."""
        return await self.client.set_room_pinned_events(room_id, event_ids)

    async def pin_message(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict:
        """Pin a Matrix event in a room."""
        return await self.client.pin_room_event(
            room_id=room_id,
            event_id=event_id,
            prepend=prepend,
        )

    async def unpin_message(self, room_id: str, event_id: str) -> dict:
        """Unpin a Matrix event in a room."""
        return await self.client.unpin_room_event(room_id=room_id, event_id=event_id)
