"""
Matrix 消息发送组件
"""

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
