"""Matrix to-device event processing for the event processor."""

from astrbot.api import logger

from ....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_KEY_REQUEST,
    M_ROOM_KEY_WITHHELD,
    MEGOLM_ALGO,
)


class MatrixEventProcessorToDeviceOperationsMixin:
    """Handle encrypted room-key, verification, and secret events."""

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
                if self.e2ee_manager:
                    try:
                        await self.e2ee_manager.handle_verification_event(
                            event_type, sender, content
                        )
                    except Exception as e:
                        logger.error(f"处理验证事件失败：{e}")
                else:
                    logger.debug(f"E2EE 未启用，忽略验证事件：{event_type}")
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
                if self.e2ee_manager:
                    try:
                        algorithm = content.get("algorithm", "unknown")
                        sender_key = content.get("sender_key")
                        masked_sender_key = (
                            sender_key[:16] if isinstance(sender_key, str) else ""
                        )
                        logger.debug(
                            f"收到加密的 to_device 消息：algorithm={algorithm} "
                            f"sender_key={masked_sender_key}..."
                        )

                        decrypted = await self.e2ee_manager.decrypt_event(
                            content, sender, ""
                        )
                        logger.debug(f"解密 to_device 结果：{decrypted is not None}")
                        if decrypted:
                            inner_type = decrypted.get("type", "")
                            inner_content = decrypted.get("content", decrypted)
                            logger.debug(f"解密后的事件类型：{inner_type}")
                            if inner_type == M_ROOM_KEY:
                                sender_key = content.get("sender_key", "")
                                await self.e2ee_manager.handle_room_key(
                                    inner_content,
                                    sender_key,
                                    sender_claimed_keys=decrypted.get("keys"),
                                    sender_user_id=sender,
                                    forwarded=False,
                                )
                                logger.debug("成功处理加密的 m.room_key 事件")
                            elif inner_type == M_FORWARDED_ROOM_KEY:
                                sender_key = content.get("sender_key", "")
                                await self.e2ee_manager.handle_room_key(
                                    inner_content,
                                    sender_key,
                                    sender_claimed_keys=decrypted.get("keys"),
                                    sender_user_id=sender,
                                    forwarded=True,
                                )
                                logger.debug("成功处理加密的 m.forwarded_room_key 事件")
                            elif inner_type and inner_type.startswith(
                                "m.key.verification."
                            ):
                                logger.debug(f"收到加密的验证事件：{inner_type}")
                                await self.e2ee_manager.handle_verification_event(
                                    inner_type, sender, inner_content
                                )
                            elif inner_type == "m.secret.send":
                                logger.debug("收到加密的 m.secret.send 事件")
                                await self.e2ee_manager.handle_secret_send(
                                    sender,
                                    inner_content,
                                    content.get("sender_key", ""),
                                )
                            elif inner_type == "m.secret.request":
                                logger.debug("收到加密的 m.secret.request 事件")
                                sender_device = inner_content.get(
                                    "requesting_device_id", ""
                                )
                                await self.e2ee_manager.handle_secret_request(
                                    sender=sender,
                                    content=inner_content,
                                    sender_device=sender_device,
                                )
                            elif inner_type == "m.dummy":
                                logger.debug("收到 m.dummy 事件，忽略")
                            else:
                                logger.debug(
                                    f"收到未知的加密 to_device 事件类型：{inner_type}，内容键：{list(decrypted.keys()) if isinstance(decrypted, dict) else type(decrypted)}"
                                )
                        else:
                            # 解密失败
                            ciphertext_keys = list(content.get("ciphertext", {}).keys())
                            logger.debug(
                                f"解密 to_device 消息失败，ciphertext 目标密钥：{ciphertext_keys}"
                            )
                    except Exception as e:
                        logger.error(f"处理加密 to_device 事件失败：{e}")
                continue

            # 处理 m.forwarded_room_key 事件 (转发的 Megolm 密钥)
            if event_type == M_FORWARDED_ROOM_KEY:
                logger.warning(
                    "Ignoring m.forwarded_room_key event not encrypted with Olm"
                )
                continue

            if event_type == M_ROOM_KEY_WITHHELD:
                if self.e2ee_manager:
                    try:
                        await self.e2ee_manager.handle_room_key_withheld(
                            sender,
                            content,
                        )
                    except Exception as e:
                        logger.error(f"Failed to process m.room_key.withheld: {e}")
                continue

            # 处理 m.room_key_request 事件 (来自其他设备的密钥请求)
            if event_type == M_ROOM_KEY_REQUEST:
                if self.e2ee_manager:
                    try:
                        action = content.get("action", "")
                        requesting_device_id = content.get("requesting_device_id", "")
                        request_id = content.get("request_id", "")
                        body = content.get("body", {})

                        if action == "request":
                            # 跳过自己设备发出的请求
                            if (
                                self.e2ee_manager
                                and requesting_device_id == self.e2ee_manager.device_id
                            ):
                                logger.debug("忽略来自自己设备的密钥请求")
                                continue

                            if (
                                not isinstance(request_id, str)
                                or not request_id
                                or not isinstance(body, dict)
                                or (
                                    sender,
                                    requesting_device_id,
                                    request_id,
                                )
                                in cancelled_requests
                            ):
                                logger.debug(
                                    "Ignoring cancelled room-key request or one "
                                    "without a request_id"
                                )
                                continue

                            room_id = body.get("room_id", "")
                            session_id = body.get("session_id", "")

                            if body.get("algorithm") != MEGOLM_ALGO or not all(
                                isinstance(value, str) and value
                                for value in (
                                    requesting_device_id,
                                    room_id,
                                    session_id,
                                )
                            ):
                                logger.warning(
                                    "Ignoring malformed room-key request: "
                                    f"device={requesting_device_id or '<empty>'} "
                                    f"room={room_id or '<empty>'} "
                                    f"session={session_id or '<empty>'}"
                                )
                                continue

                            logger.debug(
                                f"收到密钥请求：来自设备 {requesting_device_id}，"
                                f"room={(room_id or '')[:16]}..., session={(session_id or '')[:8]}..."
                            )

                            # 调用 E2EE 管理器响应密钥请求
                            await self.e2ee_manager.respond_to_key_request(
                                sender=sender,
                                requesting_device_id=requesting_device_id,
                                room_id=room_id,
                                session_id=session_id,
                            )
                        elif action == "request_cancellation":
                            if not all(
                                isinstance(value, str) and value
                                for value in (request_id, requesting_device_id)
                            ):
                                logger.warning(
                                    "Ignoring malformed room-key request cancellation"
                                )
                                continue
                            logger.debug(
                                f"密钥请求已取消：device={requesting_device_id}"
                            )
                    except Exception as e:
                        logger.error(f"处理 m.room_key_request 事件失败：{e}")
                continue

            # 处理 m.secret.request 事件 (来自其他设备的秘密请求)
            if event_type == "m.secret.request":
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
                continue

            # Log other event types
            logger.debug(f"收到设备间事件：{event_type} 来自 {sender}")
