"""Custom Matrix event send methods."""

from typing import Any


class SenderMediaCustomMixin:
    """Send custom Matrix room events."""

    async def send_custom_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """
        Send a custom Matrix room event.

        Args:
            room_id: Room ID
            event_type: Matrix event type, e.g. `m.room.message` or `org.example.custom`
            content: Event content dictionary
            reply_to: Optional event ID to reply to
            thread_root: Optional thread root event ID
            use_thread: Whether to send as threaded event

        Returns:
            Matrix API response (usually containing event_id), or None on failure
        """
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(content, dict):
            raise ValueError("content must be a dict")

        from .....events.common import send_content

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_content(
            client=self.client,
            content=dict(content),
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            is_encrypted_room=is_encrypted_room,
            e2ee_manager=self.e2ee_manager,
            msg_type=event_type,
        )

    async def send_custom_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """Alias of send_custom_message."""
        return await self.send_custom_message(
            room_id=room_id,
            event_type=event_type,
            content=content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
        )
