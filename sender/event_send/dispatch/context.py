"""Context preparation for Matrix message-chain dispatch."""

from dataclasses import dataclass
from typing import Any

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain, Reply

from ....constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES


@dataclass(slots=True)
class SendContext:
    """Resolved state shared by every message component sender."""

    client: Any
    chain_to_send: list[Any]
    room_id: str
    reply_to: str | None
    thread_root: str | None
    use_thread: bool
    original_message_info: dict | None
    e2ee_manager: Any | None
    upload_size_limit: int
    use_notice: bool
    thread_is_falling_back: bool
    is_encrypted_room: bool


async def build_send_context(
    client: Any,
    message_chain: MessageChain,
    room_id: str,
    *,
    reply_to: str | None = None,
    thread_root: str | None = None,
    use_thread: bool = False,
    original_message_info: dict | None = None,
    e2ee_manager: Any | None = None,
    max_upload_size: int | None = None,
    use_notice: bool = False,
    thread_is_falling_back: bool | None = None,
) -> SendContext:
    """Resolve encryption, reply, thread, and plain-text merge state."""
    upload_size_limit = max_upload_size or DEFAULT_MAX_UPLOAD_SIZE_BYTES
    is_encrypted_room = False
    if e2ee_manager:
        try:
            is_encrypted_room = await client.is_room_encrypted(room_id)
            if is_encrypted_room:
                logger.debug(f"房间 {room_id} 已加密（E2EE）")
        except Exception as exc:
            logger.debug(f"检查房间加密状态失败：{exc}")

    if reply_to is None:
        for segment in message_chain.chain:
            if isinstance(segment, Reply) and getattr(segment, "id", None):
                reply_to = str(segment.id)
                break

    if thread_is_falling_back is None:
        thread_is_falling_back = bool(use_thread and thread_root and reply_to is None)

    return SendContext(
        client=client,
        chain_to_send=_merge_plain_segments(message_chain),
        room_id=room_id,
        reply_to=reply_to,
        thread_root=thread_root,
        use_thread=use_thread,
        original_message_info=original_message_info,
        e2ee_manager=e2ee_manager,
        upload_size_limit=upload_size_limit,
        use_notice=use_notice,
        thread_is_falling_back=thread_is_falling_back,
        is_encrypted_room=is_encrypted_room,
    )


def _merge_plain_segments(message_chain: MessageChain) -> list[Any]:
    """Coalesce adjacent plain components before dispatching them."""
    merged_chain: list[Any] = []
    for segment in message_chain.chain:
        if (
            isinstance(segment, Plain)
            and merged_chain
            and isinstance(merged_chain[-1], Plain)
        ):
            merged_chain[-1].text += segment.text
        else:
            merged_chain.append(segment)
    return merged_chain
