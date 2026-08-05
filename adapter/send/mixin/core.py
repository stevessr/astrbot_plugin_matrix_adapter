"""Session-oriented Matrix adapter send operations."""

from astrbot.api import logger
from astrbot.api.event import MessageChain

from ..formatting import build_message_chain, format_plain_segment
from .config import _get_plugin_config
from .context import MatrixAdapterSendContextMixin
from .delivery import MatrixAdapterSendDeliveryMixin
from .typing import MatrixAdapterSendTypingMixin


class MatrixAdapterSendCoreMixin(
    MatrixAdapterSendContextMixin,
    MatrixAdapterSendDeliveryMixin,
    MatrixAdapterSendTypingMixin,
):
    """Session-oriented send operations."""

    async def send_by_session(
        self, session, message_chain: MessageChain, reply_to: str = None
    ):
        try:
            room_id = session.session_id

            send_typing = _get_plugin_config().send_typing

            if send_typing:
                await self._start_typing(room_id)

            (
                reply_to,
                thread_root,
                use_thread,
                original_message_info,
            ) = await self._resolve_reply_context(message_chain, reply_to, room_id)

            new_message_chain = build_message_chain(message_chain, reply_to)
            if new_message_chain is not None:
                await self._send_chain(
                    new_message_chain,
                    room_id,
                    reply_to=reply_to,
                    thread_root=thread_root,
                    use_thread=use_thread,
                    original_message_info=original_message_info,
                )

            if send_typing:
                await self._stop_typing(room_id)
        except Exception as e:
            logger.error(f"通过会话发送消息失败：{e}")

    async def _send_segment(
        self,
        room_id: str,
        segment,
        header_comps: list,
        reply_to: str,
        thread_root: str,
        use_thread: bool,
        original_message_info: dict | None = None,
    ):
        """发送单个消息段落"""
        processed_segment = format_plain_segment(
            segment,
            reply_to=reply_to,
            has_header=bool(header_comps),
        )
        chain = (
            [*header_comps, processed_segment] if header_comps else [processed_segment]
        )

        from ....events.matrix import MatrixPlatformEvent

        await MatrixPlatformEvent.send_with_client(
            self.client,
            MessageChain(chain),
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            max_upload_size=self.max_upload_size,
            use_notice=self._matrix_config.use_notice,
        )
