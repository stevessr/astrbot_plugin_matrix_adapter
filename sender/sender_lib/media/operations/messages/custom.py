"""Custom Matrix event send methods."""

import html
from typing import Any

from ......constants import MATRIX_HTML_FORMAT


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

    async def send_math_message(
        self,
        room_id: str,
        latex: str,
        *,
        fallback: str | None = None,
        block: bool = False,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        use_notice: bool | None = None,
    ) -> dict | None:
        """Send a Matrix v1.11 / MSC2191 mathematical message.

        Inline maths uses ``span[data-mx-maths]`` and block maths uses
        ``div[data-mx-maths]`` inside ``org.matrix.custom.html``. ``body`` is
        always retained as the plain-text fallback for clients which do not
        render mathematical notation.
        """
        if not isinstance(latex, str) or not latex:
            raise ValueError("latex must be a non-empty string")
        plain = fallback if isinstance(fallback, str) and fallback else latex
        tag = "div" if block else "span"
        formatted = (
            f'<{tag} data-mx-maths="{html.escape(latex, quote=True)}">'
            f"{html.escape(plain)}</{tag}>"
        )
        notice = self.use_notice if use_notice is None else bool(use_notice)
        content = {
            "msgtype": "m.notice" if notice else "m.text",
            "body": plain,
            "format": MATRIX_HTML_FORMAT,
            "formatted_body": formatted,
        }
        return await self.send_custom_message(
            room_id=room_id,
            event_type="m.room.message",
            content=content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
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
