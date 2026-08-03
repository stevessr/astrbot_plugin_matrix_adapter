"""MSC4140 delayed room and state event send operations."""

import secrets
import time
from typing import Any

from ...constants import (
    MSC4140_DELAY_KEY,
    MSC4140_PARENT_DELAY_ID_KEY,
)
from ..path_utils import quote_path_segment


class DelayedEventSendingMixin:
    """Send cancellable delayed room and state events."""

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
        params: dict[str, Any] = {MSC4140_DELAY_KEY: delay_ms}
        if parent_delay_id:
            params[MSC4140_PARENT_DELAY_ID_KEY] = parent_delay_id
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
        params: dict[str, Any] = {MSC4140_DELAY_KEY: delay_ms}
        if parent_delay_id:
            params[MSC4140_PARENT_DELAY_ID_KEY] = parent_delay_id
        return await self._request("PUT", endpoint, data=content, params=params)
