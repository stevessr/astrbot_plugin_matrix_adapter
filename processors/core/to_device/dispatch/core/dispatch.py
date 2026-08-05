"""Per-event to-device dispatch."""

from astrbot.api import logger

from ......constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_KEY_REQUEST,
    M_ROOM_KEY_WITHHELD,
)


async def _dispatch_to_device_event(
    self, event: dict, cancelled_requests: set[tuple[str, str, str]]
) -> None:
    event_type = event.get("type")
    sender = event.get("sender")
    if not isinstance(event_type, str) or not event_type:
        logger.warning("Skipping to-device event without a type")
        return
    if not isinstance(sender, str) or not sender:
        logger.warning(f"to_device 事件缺少 sender，跳过：type={event_type}")
        return
    content = event.get("content", {})
    if not isinstance(content, dict):
        logger.warning(f"Invalid to-device content for type={event_type}")
        return

    logger.debug(f"处理 to_device 事件：type={event_type} sender={sender}")

    # 处理验证事件
    if event_type.startswith("m.key.verification."):
        await self._handle_verification_to_device(event_type, sender, content)
        return

    # 处理 m.room_key 事件 (Megolm 密钥分发)
    if event_type == M_ROOM_KEY:
        # m.room_key is an Olm plaintext event type. Accepting a raw
        # to-device copy lets the homeserver inject arbitrary Megolm
        # sessions, so it must always be discarded here.
        logger.warning("Ignoring m.room_key event not encrypted with Olm")
        return

    # 处理 m.room.encrypted to_device 消息 (通常包含 m.room_key)
    if event_type == M_ROOM_ENCRYPTED:
        await self._handle_encrypted_to_device(sender, content)
        return

    # 处理 m.forwarded_room_key 事件 (转发的 Megolm 密钥)
    if event_type == M_FORWARDED_ROOM_KEY:
        logger.warning("Ignoring m.forwarded_room_key event not encrypted with Olm")
        return

    if event_type == M_ROOM_KEY_WITHHELD:
        await self._handle_room_key_withheld(sender, content)
        return

    # 处理 m.room_key_request 事件 (来自其他设备的密钥请求)
    if event_type == M_ROOM_KEY_REQUEST:
        await self._handle_room_key_request(sender, content, cancelled_requests)
        return

    # 处理 m.secret.request 事件 (来自其他设备的秘密请求)
    if event_type == "m.secret.request":
        await self._handle_secret_request(sender, content)
        return

    # Log other event types
    logger.debug(f"收到设备间事件：{event_type} 来自 {sender}")
