"""Encrypted and plain streaming message sends."""

from astrbot.api import logger

from ....constants import M_ROOM_ENCRYPTED
from ...events.common import _copy_cleartext_relates_to
from .payload import _encrypted_payload_without_relation


async def send_message_encrypted(
    client,
    e2ee_manager,
    room_id: str,
    msg_type: str,
    content: dict,
    tracker_metadata: dict | None = None,
) -> dict:
    """加密并发送消息"""
    try:
        encrypted = await e2ee_manager.encrypt_message(
            room_id,
            msg_type,
            _encrypted_payload_without_relation(content),
        )
        if encrypted:
            _copy_cleartext_relates_to(encrypted, content)
            return await client.send_message(
                room_id=room_id,
                msg_type=M_ROOM_ENCRYPTED,
                content=encrypted,
                tracker_metadata=tracker_metadata,
            )
        logger.warning("流式发送：加密失败，回退到未加密发送")
    except Exception as e:
        logger.warning(f"流式发送：加密异常 {e}，回退到未加密发送")
    return await client.send_message(
        room_id=room_id,
        msg_type=msg_type,
        content=content,
        tracker_metadata=tracker_metadata,
    )


async def send_message_plain(
    client,
    room_id: str,
    msg_type: str,
    content: dict,
    tracker_metadata: dict | None = None,
) -> dict:
    """发送未加密消息"""
    return await client.send_message(
        room_id=room_id,
        msg_type=msg_type,
        content=content,
        tracker_metadata=tracker_metadata,
    )
