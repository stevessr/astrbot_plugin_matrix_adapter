"""Room call-decline and message-edit send operations."""

import time
from typing import Any

from .....constants import (
    M_ROOM_MESSAGE,
    MSC4310_RTC_DECLINE,
    MSGTYPE_TEXT,
    REL_TYPE_REFERENCE,
    REL_TYPE_REPLACE,
)


class MessageRoomRelationSendMixin:
    """Send call-decline events and edits with Matrix relations."""

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
