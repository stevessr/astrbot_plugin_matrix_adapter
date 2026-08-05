"""Room call-decline send operation."""

from typing import Any

from ......constants import MSC4310_RTC_DECLINE, REL_TYPE_REFERENCE


class MessageCallDeclineMixin:
    """Send MatrixRTC call decline events."""

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


__all__ = ["MessageCallDeclineMixin"]
