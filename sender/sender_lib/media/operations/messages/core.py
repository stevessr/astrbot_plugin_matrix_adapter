"""Message and media send methods."""

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video


class SenderMediaCoreMixin:
    """Send regular messages and media segments."""

    async def send_message(
        self,
        room_id: str,
        message_chain: MessageChain,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool | None = None,
    ) -> int:
        """
        Send a message to a room
        """
        from .....event_send import send_with_client_impl

        resolved_use_notice = self.use_notice if use_notice is None else use_notice
        return await send_with_client_impl(
            client=self.client,
            message_chain=message_chain,
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            e2ee_manager=self.e2ee_manager,
            use_notice=resolved_use_notice,
        )

    async def send_video(
        self,
        room_id: str,
        video: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool | None = None,
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
        use_notice: bool | None = None,
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
