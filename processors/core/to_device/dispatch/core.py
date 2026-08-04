"""Matrix to-device event processing orchestration."""

from astrbot.api import logger

from .....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_KEY_REQUEST,
    M_ROOM_KEY_WITHHELD,
)


class MatrixEventProcessorToDeviceCoreMixin:
    """Handle encrypted room-key, verification, and secret events."""

    async def _handle_verification_to_device(
        self, event_type: str, sender: str, content: dict
    ) -> None:
        if self.e2ee_manager:
            try:
                await self.e2ee_manager.handle_verification_event(
                    event_type, sender, content
                )
            except Exception as e:
                logger.error(f"处理验证事件失败：{e}")
        else:
            logger.debug(f"E2EE 未启用，忽略验证事件：{event_type}")

    async def _handle_secret_request(self, sender: str, content: dict) -> None:
        if self.e2ee_manager:
            try:
                # 获取发送设备 ID
                sender_device = content.get("requesting_device_id", "")
                await self.e2ee_manager.handle_secret_request(
                    sender=sender,
                    content=content,
                    sender_device=sender_device,
                )
            except Exception as e:
                logger.error(f"处理 m.secret.request 事件失败：{e}")

    async def process_to_device_events(self, events: list):
        """
        Process to-device events

        Args:
            events: List of to-device events
        """
        if events:
            logger.debug(f"收到 {len(events)} 个 to_device 事件")

        # Import available room keys before answering sibling-device requests,
        # then handle those requests before unrelated verification traffic.
        key_event_types = {M_ROOM_ENCRYPTED}
        cancelled_requests: set[tuple[str, str, str]] = set()
        for event in events:
            if not isinstance(event, dict) or event.get("type") != M_ROOM_KEY_REQUEST:
                continue
            sender = event.get("sender")
            event_content = event.get("content")
            if not isinstance(sender, str) or not isinstance(event_content, dict):
                continue
            if event_content.get("action") != "request_cancellation":
                continue
            device_id = event_content.get("requesting_device_id")
            request_id = event_content.get("request_id")
            if (
                isinstance(device_id, str)
                and device_id
                and isinstance(request_id, str)
                and request_id
            ):
                cancelled_requests.add((sender, device_id, request_id))
        events = sorted(
            events,
            key=lambda event: (
                0
                if isinstance(event, dict) and event.get("type") in key_event_types
                else (
                    1
                    if isinstance(event, dict)
                    and event.get("type") == M_ROOM_KEY_REQUEST
                    and (event.get("content") or {}).get("action") == "request"
                    else 2
                )
            ),
        )

        for event in events:
            event_type = event.get("type")
            sender = event.get("sender")
            if not isinstance(event_type, str) or not event_type:
                logger.warning("Skipping to-device event without a type")
                continue
            if not isinstance(sender, str) or not sender:
                logger.warning(f"to_device 事件缺少 sender，跳过：type={event_type}")
                continue
            content = event.get("content", {})
            if not isinstance(content, dict):
                logger.warning(f"Invalid to-device content for type={event_type}")
                continue

            logger.debug(f"处理 to_device 事件：type={event_type} sender={sender}")

            # 处理验证事件
            if event_type.startswith("m.key.verification."):
                await self._handle_verification_to_device(event_type, sender, content)
                continue

            # 处理 m.room_key 事件 (Megolm 密钥分发)
            if event_type == M_ROOM_KEY:
                # m.room_key is an Olm plaintext event type. Accepting a raw
                # to-device copy lets the homeserver inject arbitrary Megolm
                # sessions, so it must always be discarded here.
                logger.warning("Ignoring m.room_key event not encrypted with Olm")
                continue

            # 处理 m.room.encrypted to_device 消息 (通常包含 m.room_key)
            if event_type == M_ROOM_ENCRYPTED:
                await self._handle_encrypted_to_device(sender, content)
                continue

            # 处理 m.forwarded_room_key 事件 (转发的 Megolm 密钥)
            if event_type == M_FORWARDED_ROOM_KEY:
                logger.warning(
                    "Ignoring m.forwarded_room_key event not encrypted with Olm"
                )
                continue

            if event_type == M_ROOM_KEY_WITHHELD:
                await self._handle_room_key_withheld(sender, content)
                continue

            # 处理 m.room_key_request 事件 (来自其他设备的密钥请求)
            if event_type == M_ROOM_KEY_REQUEST:
                await self._handle_room_key_request(sender, content, cancelled_requests)
                continue

            # 处理 m.secret.request 事件 (来自其他设备的秘密请求)
            if event_type == "m.secret.request":
                await self._handle_secret_request(sender, content)
                continue

            # Log other event types
            logger.debug(f"收到设备间事件：{event_type} 来自 {sender}")
