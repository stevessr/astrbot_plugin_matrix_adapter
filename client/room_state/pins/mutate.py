"""Pinned-event mutation operations."""

from typing import Any


class RoomPinnedMutateMixin:
    """Pin and unpin individual events."""

    async def pin_room_event(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict[str, Any]:
        """
        Add an event to the room's pinned events.

        Args:
            room_id: Room ID
            event_id: Event ID to pin
            prepend: Put the event at the front instead of appending it

        Returns:
            Response with event_id
        """
        event_id = str(event_id or "").strip()
        if not event_id:
            raise ValueError("event_id is required")

        pinned = await self.get_room_pinned_events(room_id)
        pinned = [existing for existing in pinned if existing != event_id]
        if prepend:
            pinned.insert(0, event_id)
        else:
            pinned.append(event_id)
        return await self.set_room_pinned_events(room_id, pinned)

    async def unpin_room_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Remove an event from the room's pinned events.

        Args:
            room_id: Room ID
            event_id: Event ID to unpin

        Returns:
            Response with event_id
        """
        event_id = str(event_id or "").strip()
        if not event_id:
            raise ValueError("event_id is required")

        pinned = [
            existing
            for existing in await self.get_room_pinned_events(room_id)
            if existing != event_id
        ]
        return await self.set_room_pinned_events(room_id, pinned)
