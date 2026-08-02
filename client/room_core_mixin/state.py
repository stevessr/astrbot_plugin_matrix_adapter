"""Room state retrieval and update operations."""

from typing import Any

from ...constants import M_ROOM_ENCRYPTION
from ..path_utils import quote_path_segment


class RoomCoreStateMixin:
    """Read and write Matrix room state events."""

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """
        Get full state for a room

        Args:
            room_id: Room ID

        Returns:
            List of state events
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state"
        return await self._request("GET", endpoint)

    async def is_room_encrypted(self, room_id: str) -> bool:
        """
        Check if a room has encryption enabled

        Args:
            room_id: Room ID

        Returns:
            True if room is encrypted
        """
        try:
            state = await self.get_room_state(room_id)
            for event in state:
                if event.get("type") == M_ROOM_ENCRYPTION:
                    return True
            return False
        except Exception:
            return False

    async def get_room_state_event(
        self, room_id: str, event_type: str, state_key: str = ""
    ) -> dict[str, Any]:
        """
        Get a specific state event from a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., im.vector.modular.widgets)
            state_key: State key (widget ID for widgets)

        Returns:
            State event content
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        state = quote_path_segment(state_key)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/{event}/{state}"
        return await self._request("GET", endpoint)

    async def set_room_state_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        state_key: str = "",
    ) -> dict[str, Any]:
        """
        Set a state event in a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., im.vector.modular.widgets)
            content: Event content
            state_key: State key (widget ID for widgets)

        Returns:
            Response with event_id
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        state = quote_path_segment(state_key)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/{event}/{state}"
        return await self._request("PUT", endpoint, data=content)


__all__ = ["RoomCoreStateMixin"]
