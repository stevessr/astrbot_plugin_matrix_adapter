"""Individual room event handling orchestration."""

from .....constants import (
    M_KEY_VERIFICATION_REQUEST,
    M_LOCATION,
    M_REACTION,
    M_ROOM_ENCRYPTED,
    M_ROOM_MEMBER,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    M_STICKER,
)
from .....events.call import is_call_event_type
from ...states import _is_room_state_event_type


class MatrixEventProcessorRoomEventsCoreMixin:
    """Handle individual Matrix room events."""

    async def _handle_event(self, room, event_data: dict):
        """
        Handle a single event

        Args:
            room: Room object
            event_data: Event data
        """
        event_type = event_data.get("type", "")
        content = event_data.get("content", {})
        msgtype = content.get("msgtype", "")

        # Handle membership updates to keep profile cache fresh
        if event_type == M_ROOM_MEMBER:
            await self._handle_membership_event(room, event_data)
            return

        # Handle other room state updates
        if _is_room_state_event_type(event_type) and "state_key" in event_data:
            await self._handle_room_state_update(room, event_data, event_type)
            return

        # Handle in-room verification events
        # Matrix spec: standalone verification events have type m.key.verification.*
        # But in-room verification REQUEST is sent as m.room.message with msgtype m.key.verification.request
        if event_type and event_type.startswith("m.key.verification."):
            await self._handle_in_room_verification_event(room, event_data)
            return

        # Handle VoIP / MatrixRTC (live) call events. These are surfaced as
        # system events when enabled via config; otherwise ignored (the bot
        # cannot participate in WebRTC media directly).
        if event_type and is_call_event_type(event_type):
            await self._handle_call_event(room, event_data)
            return

        # Check for in-room verification request (m.room.message with msgtype m.key.verification.request)
        if event_type == M_ROOM_MESSAGE and msgtype == M_KEY_VERIFICATION_REQUEST:
            await self._handle_in_room_verification_event(room, event_data)
            return

        # Handle redaction: apply to cached room state
        if event_type == M_ROOM_REDACTION:
            await self._handle_redaction_event(room, event_data, content)
            return

        if event_type in (
            M_ROOM_MESSAGE,
            M_ROOM_ENCRYPTED,
            M_STICKER,
            M_REACTION,
            M_LOCATION,
            "m.poll.start",
            "m.poll.response",
            "m.poll.end",
            "org.matrix.msc3488.location",
            "org.matrix.msc3381.poll.start",
            "org.matrix.msc3381.poll.response",
            "org.matrix.msc3381.poll.end",
            "m.beacon",
            "m.beacon_info",
            "org.matrix.msc3672.beacon",
            "org.matrix.msc3672.beacon_info",
        ):
            await self._handle_message_event(room, event_data)
