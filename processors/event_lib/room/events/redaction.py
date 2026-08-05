"""Redaction handling for Matrix room events."""

from .....client.event_types import parse_event


class MatrixEventProcessorRoomRedactionMixin:
    """Handle redaction: apply to cached room state."""

    async def _handle_redaction_event(
        self, room, event_data: dict, content: dict
    ) -> bool:
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
        return True
