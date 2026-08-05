"""In-room verification event handling for Matrix room events."""


class MatrixEventProcessorRoomVerificationMixin:
    """Handle in-room verification events.

    Matrix spec: standalone verification events have type m.key.verification.*
    But in-room verification REQUEST is sent as m.room.message with msgtype
    m.key.verification.request.
    """

    async def _handle_in_room_verification_event(self, room, event_data: dict) -> bool:
        await self._handle_in_room_verification(room, event_data)
        return True
