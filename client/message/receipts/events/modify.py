"""Event redaction and reporting operations."""

import time
from typing import Any

from .....constants import M_ROOM_REDACTION
from ....path_utils import quote_path_segment


class MessageEventModifyMixin:
    """Redact and report Matrix events."""

    async def redact_event(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Redact an event

        Args:
            room_id: Room ID
            event_id: Event ID to redact
            reason: Optional reason
            txn_id: Optional transaction ID

        Returns:
            Response with event_id
        """
        if txn_id is None:
            txn_id = f"redact_{int(time.time() * 1000)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)
        data: dict[str, Any] = {}
        if reason:
            data["reason"] = reason
        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="redact_event",
                room_id=room_id,
                event_type=M_ROOM_REDACTION,
                content=data,
                metadata={"event_id": event_id, "reason": reason},
            )
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/redact/{event}/{txn}"
        try:
            response = await self._request("PUT", endpoint, data=data)
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
        return response

    async def report_event(
        self, room_id: str, event_id: str, score: int = 0, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Report an event

        Args:
            room_id: Room ID
            event_id: Event ID to report
            score: Negative score for abuse (-100..0)
            reason: Optional reason

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/report/{event}"
        data: dict[str, Any] = {"score": score}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)
