"""Individual room event handling operations."""

from astrbot.api import logger

from ....client.event_types import parse_event
from ....constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
)
from ....events.call import is_call_event_type
from ..states import VISIBLE_ROOM_STATE_EVENT_TYPES, _is_room_state_event_type


class MatrixEventProcessorRoomEventsMixin:
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
            event_id = event_data.get("event_id")
            if event_id and self._is_message_processed(event_id):
                return
            await self._handle_member_event(room, event_data)
            event = parse_event(event_data, room.room_id)
            await self._process_member_event(room, event)
            return

        # Handle other room state updates
        if _is_room_state_event_type(event_type) and "state_key" in event_data:
            previous_history_visibility = getattr(room, "history_visibility", None)
            self._apply_room_state_event(room, event_data)
            e2ee_manager = getattr(self, "e2ee_manager", None)
            if event_type == M_ROOM_HISTORY_VISIBILITY and e2ee_manager:
                on_visibility_changed = getattr(
                    e2ee_manager,
                    "on_history_visibility_changed",
                    None,
                )
                if callable(on_visibility_changed):
                    try:
                        await on_visibility_changed(
                            room.room_id,
                            previous_history_visibility,
                            room.history_visibility,
                        )
                    except Exception as e:
                        logger.warning(f"更新加密历史共享状态失败：{e}")
            elif event_type == M_ROOM_ENCRYPTION and e2ee_manager:
                set_encryption_config = getattr(
                    e2ee_manager,
                    "set_room_encryption_config",
                    None,
                )
                if callable(set_encryption_config):
                    set_encryption_config(room.room_id, room.encryption or {})
            await self._persist_room_state(room)

            # Process notable state changes as system events for user visibility
            if event_type in VISIBLE_ROOM_STATE_EVENT_TYPES:
                event = parse_event(event_data, room.room_id)
                await self._process_room_state_event(room, event)

            return

        # Handle in-room verification events
        # Matrix spec: standalone verification events have type m.key.verification.*
        # But in-room verification REQUEST is sent as m.room.message with msgtype m.key.verification.request
        if event_type and event_type.startswith("m.key.verification."):
            await self._handle_in_room_verification(room, event_data)
            return

        # Handle VoIP / MatrixRTC (live) call events. These are surfaced as
        # system events when enabled via config; otherwise ignored (the bot
        # cannot participate in WebRTC media directly).
        if event_type and is_call_event_type(event_type):
            await self._process_call_event(room, event_data)
            return

        # Check for in-room verification request (m.room.message with msgtype m.key.verification.request)
        if event_type == M_ROOM_MESSAGE and msgtype == "m.key.verification.request":
            await self._handle_in_room_verification(room, event_data)
            return

        # Handle redaction: apply to cached room state
        if event_type == M_ROOM_REDACTION:
            redact_event_id = content.get("redacts", "")
            if redact_event_id and hasattr(room, "state_events"):
                removed = False
                for key in list(room.state_events.keys()):
                    ev = room.state_events.get(key, {})
                    if isinstance(ev, dict) and ev.get("event_id") == redact_event_id:
                        del room.state_events[key]
                        removed = True
                if removed:
                    await self._persist_room_state(room)
            event = parse_event(event_data, room.room_id)
            await self._process_message_event(room, event)
            return

        if event_type in (
            M_ROOM_MESSAGE,
            M_ROOM_ENCRYPTED,
            "m.sticker",
            "m.reaction",
            "m.location",
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
            # Parse plaintext message event, encrypted event, sticker, or poll event
            event = parse_event(event_data, room.room_id)
            await self._process_message_event(room, event)

    pass
