"""Room state retrieval and update operations."""

from typing import Any

from ...constants import (
    M_ROOM_ENCRYPTION,
    M_ROOM_LIVE_MESSAGING,
    MSC4357_LIVE_MESSAGING_STATE,
)
from ..base.errors import MatrixAPIError
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
        self,
        room_id: str,
        event_type: str,
        state_key: str = "",
        format: str | None = None,
    ) -> dict[str, Any]:
        """Get a specific state event from a room.

        Matrix v1.16 adds ``format=event`` to return the full client-formatted
        state event, including metadata such as event ID, sender and timestamp.
        The default/``content`` form retains the historical content-only shape.
        """
        if format is not None and format not in {"content", "event"}:
            raise ValueError("format must be 'content', 'event', or None")

        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        state = quote_path_segment(state_key)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/{event}/{state}"
        params = {"format": format} if format is not None else None
        return await self._request("GET", endpoint, params=params)

    async def get_room_live_messaging_allowed(self, room_id: str) -> bool:
        """Probe the homeserver for the room-level MSC4357 policy.

        MSC4357 does not define a homeserver-wide ``/versions`` capability:
        Live Messages reuse ordinary ``m.room.message`` + ``m.replace`` events.
        The normative server-visible control is the room state event. Prefer a
        future stable ``m.room.live_messaging`` state event when present, then
        fall back to the current unstable
        ``org.matrix.msc4357.live_messaging`` identifier.

        A missing state event means Live Messages are enabled by default.
        Transport/auth/server failures are deliberately propagated so callers
        can conservatively fall back for the current response and retry later.
        """

        for event_type in (
            M_ROOM_LIVE_MESSAGING,
            MSC4357_LIVE_MESSAGING_STATE,
        ):
            try:
                content = await self.get_room_state_event(room_id, event_type)
            except MatrixAPIError as exc:
                # GET /state/{type}/ returns 404/M_NOT_FOUND when this optional
                # state event is absent. Absence is not lack of MSC4357 server
                # support: the proposal explicitly defaults the room to enabled.
                if exc.status == 404:
                    continue
                raise

            if not isinstance(content, dict):
                continue
            enabled = content.get("enabled")
            if isinstance(enabled, bool):
                return enabled

        return True

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
