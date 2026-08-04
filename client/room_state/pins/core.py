"""Pinned-event state read and write operations."""

from collections.abc import Iterable
from typing import Any

from ....constants import M_ROOM_PINNED_EVENTS
from ...base import MatrixAPIError
from .normalize import normalize_pinned_event_ids


class RoomPinnedStateMixin:
    """Read and replace a room's pinned event list."""

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
        return normalize_pinned_event_ids(pinned)

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
            content={"pinned": normalize_pinned_event_ids(event_ids)},
        )
