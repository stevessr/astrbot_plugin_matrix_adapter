"""
Matrix HTTP Client - Message Receipts Mixin
Provides read receipts, read markers, redaction, reporting, and event context methods
"""

import json
import time
from typing import Any

from ...constants import (
    DEFAULT_TIMEOUT_MS_30000,
    M_ROOM_REDACTION,
    MSC4446_ALLOW_BACKWARD,
)
from ..path_utils import quote_path_segment


class MessageReceiptsMixin:
    """Message receipt, redaction, and context methods for Matrix client"""

    async def send_read_receipt(
        self, room_id: str, event_id: str, thread_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge
            thread_id: Optional thread ID for per-thread receipts (MSC3771)

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}"
        data: dict[str, Any] = {}
        if thread_id:
            data["thread_id"] = thread_id
        return await self._request("POST", endpoint, data=data)

    async def send_read_receipt_private(
        self, room_id: str, event_id: str, thread_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send private read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge
            thread_id: Optional thread ID for per-thread receipts (MSC3771)

        Returns:
            Response data
        """
        endpoint = (
            f"/_matrix/client/v3/rooms/{quote_path_segment(room_id)}"
            f"/receipt/m.read.private/{quote_path_segment(event_id)}"
        )
        data: dict[str, Any] = {}
        if thread_id:
            data["thread_id"] = thread_id
        return await self._request("POST", endpoint, data=data)

    async def send_read_markers(
        self,
        room_id: str,
        fully_read: str | None = None,
        read: str | None = None,
        allow_backward: bool = False,
    ) -> dict[str, Any]:
        """
        Set read markers for a room

        Args:
            room_id: Room ID
            fully_read: Event ID for fully_read marker
            read: Event ID for read marker
            allow_backward: MSC4446 — allow moving ``m.fully_read`` back to an earlier
                event. Writes both the stable key ``allow_backward`` and the unstable
                key ``com.beeper.allow_backward`` for servers that haven't adopted the
                stable name yet.
                Note: read receipts (``m.read`` / ``m.read.private``) remain monotonic.

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/read_markers"
        data: dict[str, Any] = {}
        if fully_read:
            data["m.fully_read"] = fully_read
        if read:
            data["m.read"] = read
        if allow_backward:
            data["allow_backward"] = True
            data[MSC4446_ALLOW_BACKWARD] = True
        return await self._request("POST", endpoint, data=data)

    async def send_fully_read_receipt(
        self,
        room_id: str,
        event_id: str,
        *,
        allow_backward: bool = False,
    ) -> dict[str, Any]:
        """
        Set the fully read marker to a specific event via the receipt endpoint
        (MSC4446 aware).

        Uses ``POST /_matrix/client/v3/rooms/{roomId}/receipt/m.fully_read/{eventId}``,
        writing both stable and unstable keys when ``allow_backward=True`` to allow
        moving the marker back to an earlier event. This endpoint only accepts
        ``m.fully_read`` receipt type; other types are rejected with 400.

        Args:
            room_id: Room ID
            event_id: Event ID to mark as fully read
            allow_backward: Allow moving the marker to an earlier event

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/receipt/m.fully_read/{event}"
        data: dict[str, Any] = {}
        if allow_backward:
            data["allow_backward"] = True
            data[MSC4446_ALLOW_BACKWARD] = True
        return await self._request("POST", endpoint, data=data)

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

    async def get_event_context(
        self,
        room_id: str,
        event_id: str,
        limit: int | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get context around an event

        Args:
            room_id: Room ID
            event_id: Event ID
            limit: Optional limit
            filter: Optional filter

        Returns:
            Context response
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/context/{event}"
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if filter is not None:
            params["filter"] = json.dumps(filter, ensure_ascii=False)
        return await self._request("GET", endpoint, params=params)

    async def get_event_relations(
        self,
        room_id: str,
        event_id: str,
        rel_type: str,
        event_type: str | None = None,
        from_token: str | None = None,
        to_token: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Get relations for an event

        Args:
            room_id: Room ID
            event_id: Event ID
            rel_type: Relation type (e.g., m.annotation)
            event_type: Optional event type filter
            from_token: Pagination token
            to_token: Pagination token
            limit: Optional limit

        Returns:
            Relations response
        """
        room = quote_path_segment(room_id)
        event = quote_path_segment(event_id)
        relation = quote_path_segment(rel_type)
        path = f"/_matrix/client/v3/rooms/{room}/relations/{event}/{relation}"
        if event_type:
            path += f"/{quote_path_segment(event_type)}"
        params: dict[str, Any] = {}
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token
        if limit is not None:
            params["limit"] = limit
        return await self._request("GET", path, params=params)

    async def set_typing(
        self, room_id: str, typing: bool = True, timeout: int = DEFAULT_TIMEOUT_MS_30000
    ) -> dict[str, Any]:
        """
        Set typing status in a room

        Args:
            room_id: Room ID
            typing: Whether the user is typing
            timeout: Typing timeout in milliseconds

        Returns:
            Response data
        """
        room = quote_path_segment(room_id)
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/typing/{user}"
        data = {"typing": typing, "timeout": timeout} if typing else {"typing": False}
        return await self._request("PUT", endpoint, data=data)