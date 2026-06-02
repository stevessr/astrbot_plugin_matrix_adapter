"""
Matrix HTTP Client - Delayed Events Mixin (MSC4140)

Implements cancellable delayed (future) events:
- Send a delayed room event / state event with a `delay` query parameter
- Manage delayed events via /delayed_events endpoints (send / restart / cancel / list)

Spec proposal: https://github.com/matrix-org/matrix-spec-proposals/pull/4140
"""

import secrets
import time
from typing import Any

from ..constants import MSC4140_DELAYED_EVENTS_PATH
from .path_utils import quote_path_segment


class DelayedEventsMixin:
    """MSC4140 delayed/future events."""

    async def send_delayed_room_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        delay_ms: int,
        parent_delay_id: str | None = None,
        txn_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a one-shot delayed (future) room event (MSC4140).

        Args:
            room_id: Target room ID
            event_type: Event type, e.g. ``m.room.message``
            content: Event content
            delay_ms: Delay before the server fires the event, in milliseconds.
                Must be positive.
            parent_delay_id: Optional delay group ID this event belongs to.
            txn_id: Optional client-supplied transaction ID.

        Returns:
            Response from the server, expected to contain ``delay_id``.
        """
        if delay_ms <= 0:
            raise ValueError("delay_ms must be positive for delayed events")

        txn_id = txn_id or f"delay_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event}/{txn}"
        params: dict[str, Any] = {"org.matrix.msc4140.delay": delay_ms}
        if parent_delay_id:
            params["org.matrix.msc4140.parent_delay_id"] = parent_delay_id
        return await self._request("PUT", endpoint, data=content, params=params)

    async def send_delayed_state_event(
        self,
        room_id: str,
        event_type: str,
        state_key: str,
        content: dict[str, Any],
        delay_ms: int,
        parent_delay_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a delayed state event (MSC4140).

        Args:
            room_id: Target room ID
            event_type: State event type, e.g. ``m.room.topic``
            state_key: State key (usually empty string)
            content: State content
            delay_ms: Delay before the server fires the event, in milliseconds.
            parent_delay_id: Optional delay group ID this event belongs to.
        """
        if delay_ms <= 0:
            raise ValueError("delay_ms must be positive for delayed events")

        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        state = quote_path_segment(state_key)
        endpoint = f"/_matrix/client/v3/rooms/{room}/state/{event}/{state}"
        params: dict[str, Any] = {"org.matrix.msc4140.delay": delay_ms}
        if parent_delay_id:
            params["org.matrix.msc4140.parent_delay_id"] = parent_delay_id
        return await self._request("PUT", endpoint, data=content, params=params)

    async def list_delayed_events(
        self,
        from_token: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the user's currently pending delayed events (MSC4140)."""
        params: dict[str, Any] = {}
        if from_token:
            params["from"] = from_token
        if limit is not None:
            params["limit"] = limit
        return await self._request(
            "GET", MSC4140_DELAYED_EVENTS_PATH, params=params or None
        )

    async def manage_delayed_event(
        self, delay_id: str, action: str
    ) -> dict[str, Any]:
        """
        Run an action against a pending delayed event (MSC4140).

        Args:
            delay_id: The delay ID returned by ``send_delayed_*``.
            action: One of ``send``, ``restart``, ``cancel``.
        """
        action = (action or "").strip().lower()
        if action not in {"send", "restart", "cancel"}:
            raise ValueError(
                "action must be one of 'send', 'restart', 'cancel'"
            )
        delay = quote_path_segment(delay_id)
        endpoint = f"{MSC4140_DELAYED_EVENTS_PATH}/{delay}"
        return await self._request("POST", endpoint, data={"action": action})

    async def cancel_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Cancel a pending delayed event (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "cancel")

    async def restart_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Restart the timer on a pending delayed event (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "restart")

    async def fire_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Send a pending delayed event immediately (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "send")
