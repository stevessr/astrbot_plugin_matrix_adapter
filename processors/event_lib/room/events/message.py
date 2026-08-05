"""Plaintext / encrypted message event handling for Matrix room events."""

from .....client.event_types import parse_event


class MatrixEventProcessorRoomMessageMixin:
    """Handle plaintext message, encrypted event, sticker, or poll event."""

    async def _handle_message_event(self, room, event_data: dict) -> bool:
        # Parse plaintext message event, encrypted event, sticker, or poll event
        event = parse_event(event_data, room.room_id)
        await self._process_message_event(room, event)
        return True
