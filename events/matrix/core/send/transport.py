"""Matrix event send transport delegation."""

from astrbot.api.event import MessageChain


class MatrixPlatformEventTransportMixin:
    """Delegate message delivery to the sender transport implementation."""

    @staticmethod
    async def send_with_client(
        client,
        message_chain: MessageChain,
        room_id: str,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        original_message_info: dict | None = None,
        e2ee_manager=None,
        max_upload_size: int | None = None,
        use_notice: bool = False,
        thread_is_falling_back: bool | None = None,
    ) -> int:
        """使用提供的 client 将指定消息链发送到指定房间。"""
        from . import send_with_client_impl

        return await send_with_client_impl(
            client=client,
            message_chain=message_chain,
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=e2ee_manager,
            max_upload_size=max_upload_size,
            use_notice=use_notice,
            thread_is_falling_back=thread_is_falling_back,
        )


__all__ = ["MatrixPlatformEventTransportMixin"]
