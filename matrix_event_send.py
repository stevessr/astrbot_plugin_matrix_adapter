from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import (
    At,
    File,
    Image,
    Location,
    Plain,
    Record,
    Reply,
    Video,
)

from .constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from .sender.handlers import (
    send_at,
    send_audio,
    send_file,
    send_image,
    send_location,
    send_plain,
    send_sticker,
    send_video,
)
from .sticker import Sticker


def _is_sticker_component(obj) -> bool:
    """Check if object is a Sticker-like component via duck-typing."""
    if isinstance(obj, Sticker):
        return True
    class_name = type(obj).__name__
    if class_name != "Sticker":
        return False
    required_attrs = ["body", "url", "info", "to_matrix_content"]
    return all(hasattr(obj, attr) for attr in required_attrs)

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
) -> int:
    """Send a message chain using the provided client."""
    upload_size_limit = max_upload_size or DEFAULT_MAX_UPLOAD_SIZE_BYTES
    sent_count = 0

    # Check if room is encrypted
    is_encrypted_room = False
    if e2ee_manager:
        try:
            is_encrypted_room = await client.is_room_encrypted(room_id)
            if is_encrypted_room:
                logger.debug(f"房间 {room_id} 已加密，将使用 E2EE 发送消息")
        except Exception as e:
            logger.debug(f"检查房间加密状态失败：{e}")

    if reply_to is None:
        for seg in message_chain.chain:
            if isinstance(seg, Reply) and getattr(seg, "id", None):
                reply_to = str(seg.id)
                break

    merged_chain = []
    for segment in message_chain.chain:
        if (
            isinstance(segment, Plain)
            and merged_chain
            and isinstance(merged_chain[-1], Plain)
        ):
            merged_chain[-1].text += segment.text
        else:
            merged_chain.append(segment)

    chain_to_send = merged_chain

    for segment in chain_to_send:
        if isinstance(segment, Reply):
            continue
        if isinstance(segment, Plain):
            try:
                await send_plain(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    original_message_info,
                    is_encrypted_room,
                    e2ee_manager,
                    use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送文本消息失败：{e}")

        elif isinstance(segment, Image):
            try:
                await send_image(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送图片消息失败：{e}")

        elif isinstance(segment, At):
            try:
                await send_at(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理 @ 消息过程出错：{e}")

        elif isinstance(segment, File):
            try:
                await send_file(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理文件消息过程出错：{e}")

        elif isinstance(segment, Location):
            try:
                await send_location(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理位置消息过程出错：{e}")

        elif isinstance(segment, Video):
            try:
                await send_video(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理视频消息过程出错：{e}")

        elif isinstance(segment, Record):
            try:
                await send_audio(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理语音消息过程出错：{e}")

        elif _is_sticker_component(segment):
            try:
                await send_sticker(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送 sticker 失败：{e}")

    return sent_count
