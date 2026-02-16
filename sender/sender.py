"""
Matrix 消息发送组件
"""

from typing import Any

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video

# Update import: markdown_utils is now in ..utils.markdown_utils


class MatrixSender:
    def __init__(self, client, e2ee_manager=None):
        self.client = client
        self.e2ee_manager = e2ee_manager

    async def send_message(
        self,
        room_id: str,
        message_chain: MessageChain,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """
        Send a message to a room
        """
        from ..matrix_event import MatrixPlatformEvent

        return await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            e2ee_manager=self.e2ee_manager,
            use_notice=use_notice,
        )

    async def send_video(
        self,
        room_id: str,
        video: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send a video to a room (file path or http/https URL)."""
        if video.startswith("http://") or video.startswith("https://"):
            segment = Video.fromURL(video)
        else:
            segment = Video.fromFileSystem(video)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

    async def send_audio(
        self,
        room_id: str,
        audio: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send an audio clip to a room (file path or http/https URL)."""
        if audio.startswith("http://") or audio.startswith("https://"):
            segment = Record.fromURL(audio)
        else:
            segment = Record.fromFileSystem(audio)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

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

        from .handlers.common import send_content

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

    async def send_reaction(self, room_id: str, event_id: str, emoji: str) -> dict:
        """Send a reaction to a message in a room."""
        return await self.client.send_reaction(room_id, event_id, emoji)

    async def send_poll(
        self,
        room_id: str,
        question: str,
        answers: list[str],
        max_selections: int = 1,
        kind: str = "m.disclosed",
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        event_type: str = "org.matrix.msc3381.poll.start",
        poll_key: str = "org.matrix.msc3381.poll.start",
        fallback_text: str | None = None,
        fallback_html: str | None = None,
    ) -> dict | None:
        """Send a poll to a room."""
        from ..sender.handlers import send_poll

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_poll(
            self.client,
            room_id,
            question,
            answers,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            self.e2ee_manager,
            max_selections=max_selections,
            kind=kind,
            event_type=event_type,
            poll_key=poll_key,
            fallback_text=fallback_text,
            fallback_html=fallback_html,
        )

    async def send_poll_response(
        self,
        room_id: str,
        poll_start_event_id: str,
        answer_ids: list[str],
        event_type: str = "org.matrix.msc3381.poll.response",
        poll_key: str = "org.matrix.msc3381.poll.start",
    ) -> dict | None:
        """Send a response to an existing poll.

        Args:
            room_id: Room ID
            poll_start_event_id: The event ID of the poll start event
            answer_ids: List of answer IDs to vote for (e.g., ["1"] for first option)
            event_type: Event type to use (m.poll.response or org.matrix.msc3381.poll.response)
            poll_key: Poll key to use (m.poll or org.matrix.msc3381.poll.start)

        Returns:
            The response from the server, or None on failure
        """
        from ..sender.handlers import send_poll_response

        return await send_poll_response(
            self.client,
            room_id,
            poll_start_event_id,
            answer_ids,
            event_type=event_type,
            poll_key=poll_key,
        )

    async def delete_message(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict:
        """Delete (redact) a message in a room."""
        return await self.client.redact_event(
            room_id, event_id, reason=reason, txn_id=txn_id
        )
