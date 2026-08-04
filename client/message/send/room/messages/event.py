"""Custom room event send operations."""

import time
from typing import Any

from .....path_utils import quote_path_segment
from ...helpers import _build_live_message_metadata


class RoomEventSendMixin:
    """Send custom room events."""

    async def send_room_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a custom event to a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., m.key.verification.request)
            content: Event content

        Returns:
            Send response with event_id
        """
        txn_id = txn_id or f"txn_{int(time.time() * 1000)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)
        metadata = _build_live_message_metadata(content)
        if tracker_metadata:
            metadata = {**(metadata or {}), **tracker_metadata}
        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="send_room_event",
                room_id=room_id,
                event_type=event_type,
                content=content,
                metadata=metadata,
            )
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event}/{txn}"
        try:
            response = await self._request("PUT", endpoint, data=content)
        except Exception as e:
            if tracker:
                tracker.mark_failure(txn_id, e)
            if runtime_state:
                runtime_state.mark_send_failed(str(e))
            raise
        if tracker:
            tracker.mark_success(txn_id, response)
        if runtime_state:
            runtime_state.mark_send_ok()
            if metadata and metadata.get("live_message"):
                phase = str(metadata.get("phase") or "edit")
                if phase == "initial":
                    runtime_state.mark_live_message_outbound_initial()
                else:
                    runtime_state.mark_live_message_outbound_edit()
        return response
