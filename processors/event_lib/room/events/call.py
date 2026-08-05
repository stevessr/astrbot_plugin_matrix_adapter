"""VoIP / MatrixRTC call event handling for Matrix room events."""


class MatrixEventProcessorRoomCallMixin:
    """Handle VoIP / MatrixRTC (live) call events.

    These are surfaced as system events when enabled via config; otherwise
    ignored (the bot cannot participate in WebRTC media directly).
    """

    async def _handle_call_event(self, room, event_data: dict) -> bool:
        await self._process_call_event(room, event_data)
        return True
