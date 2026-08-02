"""Room message, event, and edit send operations."""

import time
from typing import Any

from ....constants import (
    M_ROOM_MESSAGE,
    MSC4310_RTC_DECLINE,
    MSGTYPE_TEXT,
    REL_TYPE_REFERENCE,
    REL_TYPE_REPLACE,
)
from ...path_utils import quote_path_segment
from .helpers import _build_live_message_metadata


class MessageRoomSendMixin:
    """Send room messages, custom events, call declines, and edits."""

    async def send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a message to a room

        Args:
            room_id: Room ID
            msg_type: Message type (e.g., m.room.message)
            content: Message content

        Returns:
            Send response with event_id
        """
        txn_id = txn_id or f"{int(time.time() * 1000)}_{id(content)}"
        tracker = getattr(self, "outbound_tracker", None)
        runtime_state = getattr(self, "runtime_state", None)
        metadata = _build_live_message_metadata(content)
        if tracker_metadata:
            metadata = {**(metadata or {}), **tracker_metadata}
        if tracker:
            tracker.record_attempt(
                txn_id=txn_id,
                action="send_message",
                room_id=room_id,
                event_type=msg_type,
                content=content,
                metadata=metadata,
            )
        room = quote_path_segment(room_id)
        event_type = quote_path_segment(msg_type)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/{event_type}/{txn}"
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
                phase = str(metadata.get("phase") or "initial")
                if phase == "initial":
                    runtime_state.mark_live_message_outbound_initial()
                else:
                    runtime_state.mark_live_message_outbound_edit()
        return response

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

    async def send_call_decline(
        self,
        room_id: str,
        notification_event_id: str,
        *,
        txn_id: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """
        Send MatrixRTC call decline event (MSC4310).

        Constructs an ``m.rtc.decline`` (unstable type ``org.matrix.msc4310.rtc.decline``)
        event with an ``m.reference`` relation to the declined ``m.rtc.notification`` event.
        Per MSC this event SHOULD NOT include intentional mentions and SHOULD NOT trigger push.

        Args:
            room_id: Room ID
            notification_event_id: Event ID of the ``m.rtc.notification`` being declined
            txn_id: Optional transaction ID
            reason: Optional human-readable decline reason (extension field, not specified by MSC)

        Returns:
            Send response with event_id
        """
        content: dict[str, Any] = {
            "m.relates_to": {
                "rel_type": REL_TYPE_REFERENCE,
                "event_id": notification_event_id,
            },
        }
        if reason:
            content["reason"] = reason
        return await self.send_room_event(
            room_id,
            MSC4310_RTC_DECLINE,
            content,
            txn_id=txn_id,
        )

    async def send_room_message(self, room_id: str, message: str) -> dict[str, Any]:
        """
        Helper to send a simple text message to a room

        Args:
            room_id: Room ID
            message: Message text

        Returns:
            Response data
        """
        return await self.send_message(
            room_id, M_ROOM_MESSAGE, {"msgtype": MSGTYPE_TEXT, "body": message}
        )

    async def edit_message(
        self,
        room_id: str,
        original_event_id: str,
        new_content: dict[str, Any],
        msg_type: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
        thread_root: str | None = None,
    ) -> dict[str, Any]:
        """
        Edit an existing message

        Args:
            room_id: Room ID
            original_event_id: Event ID of the original message
            new_content: New message content (should include 'body')
            msg_type: Message type. Defaults to ``new_content["msgtype"]`` and
                finally ``m.text`` when the content does not declare one.
            thread_root: When editing a message that lives in a thread, pass
                the thread root event ID so the edit event carries both the
                ``m.replace`` and ``m.thread`` relations (MSC4145). This keeps
                the edit aggregated inside the thread instead of appearing as a
                room-timeline event.

        Returns:
            Send response with event_id
        """
        txn_id = f"{int(time.time() * 1000)}_{id(new_content)}"
        resolved_msg_type = msg_type or new_content.get("msgtype") or MSGTYPE_TEXT
        # Construct edit content according to Matrix spec
        relates_to: dict[str, Any] = {
            "rel_type": REL_TYPE_REPLACE,
            "event_id": original_event_id,
        }
        if thread_root:
            relates_to["m.thread"] = {"event_id": thread_root}
        content = {
            "msgtype": resolved_msg_type,
            "body": f"* {new_content.get('body', '')}",  # Fallback for clients that don't support edits
            "m.new_content": {
                "msgtype": resolved_msg_type,
                "body": new_content.get("body", ""),
                **{
                    k: v for k, v in new_content.items() if k not in ["body", "msgtype"]
                },
            },
            "m.relates_to": relates_to,
        }
        return await self.send_room_event(
            room_id=room_id,
            event_type=M_ROOM_MESSAGE,
            content=content,
            txn_id=txn_id,
            tracker_metadata=tracker_metadata,
        )


__all__ = ["MessageRoomSendMixin"]
