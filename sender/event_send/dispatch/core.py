"""Component dispatch orchestration for Matrix event messages."""

from astrbot.api.event import MessageChain

from .context import SendContext, build_send_context
from .segments import send_segments


async def send_with_client_impl(
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
    """Send a message chain using the provided client."""
    context = await build_send_context(
        client,
        message_chain,
        room_id,
        reply_to=reply_to,
        thread_root=thread_root,
        use_thread=use_thread,
        original_message_info=original_message_info,
        e2ee_manager=e2ee_manager,
        max_upload_size=max_upload_size,
        use_notice=use_notice,
        thread_is_falling_back=thread_is_falling_back,
    )
    return await send_segments(context)


__all__ = ["SendContext", "send_with_client_impl"]
