"""Pinned-event state operations for Matrix rooms."""

from collections.abc import Iterable
from typing import Any

from ...constants import M_ROOM_PINNED_EVENTS
from ..base import MatrixAPIError


class RoomPinnedEventsMixin:
    """Normalize, read, and update a room's pinned event list."""

    @staticmethod
    def _normalize_pinned_event_ids(event_ids: Iterable[object] | object) -> list[str]:
        if isinstance(event_ids, str):
            values = [event_ids]
        else:
            try:
                values = list(event_ids)  # type: ignore[arg-type]
            except TypeError:
                values = [event_ids]

        pinned: list[str] = []
        seen: set[str] = set()
        for value in values:
            if value is None:
                continue
            event_id = str(value).strip()
            if not event_id or event_id in seen:
                continue
            pinned.append(event_id)
            seen.add(event_id)
        return pinned

    async def get_room_pinned_events(self, room_id: str) -> list[str]:
        """
        Get the current pinned event IDs for a room.

        Args:
            room_id: Room ID

        Returns:
            Ordered list of pinned event IDs. Missing pinned state is treated as
            an empty list.
        """
        try:
            content = await self.get_room_state_event(
                room_id=room_id,
                event_type=M_ROOM_PINNED_EVENTS,
            )
        except MatrixAPIError as e:
            if e.status == 404:
                return []
            raise

        if not isinstance(content, dict):
            return []
        pinned = content.get("pinned") or []
        if not isinstance(pinned, list):
            return []
        return self._normalize_pinned_event_ids(pinned)

    async def set_room_pinned_events(
        self, room_id: str, event_ids: Iterable[object] | object
    ) -> dict[str, Any]:
        """
        Replace the room's pinned event list.

        Args:
            room_id: Room ID
            event_ids: Event IDs to pin. Duplicates/empty values are removed
                while preserving order.

        Returns:
            Response with event_id
        """
        return await self.set_room_state_event(
            room_id=room_id,
            event_type=M_ROOM_PINNED_EVENTS,
            content={"pinned": self._normalize_pinned_event_ids(event_ids)},
        )

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
