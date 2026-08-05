"""Membership event handling for Matrix room events."""

from .....client.event_types import parse_event


class MatrixEventProcessorRoomMembershipMixin:
    """Handle membership updates to keep profile cache fresh."""

    async def _handle_membership_event(self, room, event_data: dict) -> bool:
        event_id = event_data.get("event_id")
        if event_id and self._is_message_processed(event_id):
            return True
        await self._handle_member_event(room, event_data)
        event = parse_event(event_data, room.room_id)
        await self._process_member_event(room, event)
        return True
