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
        *,
        use_legacy_endpoint: bool = False,
    ) -> dict[str, Any]:
        """Redact an event.

        Matrix v1.18 (MSC4169) allows ``m.room.redaction`` to be sent through the
        normal ``/send`` endpoint for every room version. This is now the default.
        ``use_legacy_endpoint=True`` keeps compatibility with homeservers older than
        v1.18.
        """
        if txn_id is None:
            txn_id = f"redact_{int(time.time() * 1000)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)

        data: dict[str, Any] = {}
        if not use_legacy_endpoint:
            # For room versions < 11, a v1.18+ homeserver moves this field to the
            # event's top level while accepting the same client request shape.
            data["redacts"] = event_id
        if reason:
            data["reason"] = reason

        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="redact_event",
                room_id=room_id,
                event_type=M_ROOM_REDACTION,
                content=data,
                metadata={
                    "event_id": event_id,
                    "reason": reason,
                    "stable_send_endpoint": not use_legacy_endpoint,
                },
            )

        room = quote_path_segment(room_id)
        txn = quote_path_segment(txn_id)
        if use_legacy_endpoint:
            event = quote_path_segment(event_id)
            endpoint = f"/_matrix/client/v3/rooms/{room}/redact/{event}/{txn}"
        else:
            event_type = quote_path_segment(M_ROOM_REDACTION)
            endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event_type}/{txn}"

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
        self,
        room_id: str,
        event_id: str,
        score: int | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Report an event using the Matrix v1.18 request shape (MSC4277).

        ``score`` is retained only as a source-compatible argument for callers built
        against older versions of this adapter. Matrix v1.18 removed it from the
        protocol and it is intentionally not sent to the homeserver.
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/report/{event}"
        data: dict[str, Any] = {}
        if reason is not None:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def report_room(self, room_id: str, reason: str = "") -> dict[str, Any]:
        """Report a room as inappropriate using the stable room-report endpoint."""
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/report"
        return await self._request("POST", endpoint, data={"reason": reason})

    async def report_user(self, user_id: str, reason: str = "") -> dict[str, Any]:
        """Report a Matrix user using the stable user-report endpoint."""
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/users/{user}/report"
        return await self._request("POST", endpoint, data={"reason": reason})
