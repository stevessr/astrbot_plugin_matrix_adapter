"""
Matrix Event Processor
Handles processing of Matrix events (messages, etc.)
"""

from collections.abc import Callable

from astrbot.api import logger

from ..constants import MAX_PROCESSED_MESSAGES_1000, TIMESTAMP_BUFFER_MS_1000


class MatrixEventProcessor:
    """
    Processes Matrix events
    """

    def __init__(
        self,
        client,
        user_id: str,
        startup_ts: int,
    ):
        """
        Initialize event processor

        Args:
            client: Matrix HTTP client
            user_id: Bot's user ID
            startup_ts: Startup timestamp (milliseconds) for filtering historical messages
        """
        self.client = client
        self.user_id = user_id
        self.startup_ts = startup_ts

        # Message deduplication
        self._processed_messages: set[str] = set()
        self._max_processed_messages = MAX_PROCESSED_MESSAGES_1000

        # Event callbacks
        self.on_message: Callable | None = None

        # E2EE manager (set by adapter if E2EE is enabled)
        self.e2ee_manager = None

    def set_message_callback(self, callback: Callable):
        """
        Set callback for processed messages

        Args:
            callback: Async function(room, event) -> None
        """
        self.on_message = callback

    async def process_room_events(self, room_id: str, room_data: dict):
        """
        Process events from a room

        Args:
            room_id: Room ID
            room_data: Room data from sync response
        """
        # Update import: Client event types in ..client.event_types
        from ..client.event_types import MatrixRoom

        timeline = room_data.get("timeline", {})
        events = timeline.get("events", [])

        # Build simplified room object
        room = MatrixRoom(room_id=room_id)

        # Process state events to get room information
        state_events = room_data.get("state", {}).get("events", [])
        for event in state_events:
            if event.get("type") == "m.room.member":
                user_id = event.get("state_key")
                content = event.get("content", {})
                if content.get("membership") == "join":
                    display_name = content.get("displayname", user_id)
                    room.members[user_id] = display_name
                    room.member_count += 1

        # Process timeline events
        for event_data in events:
            await self._handle_event(room, event_data)

    async def _handle_event(self, room, event_data: dict):
        """
        Handle a single event

        Args:
            room: Room object
            event_data: Event data
        """
        from ..client.event_types import parse_event

        event_type = event_data.get("type")
        content = event_data.get("content", {})
        msgtype = content.get("msgtype", "")

        # Debug: Log all event types for troubleshooting
        logger.debug(
            f"[EventProcessor] 收到房间事件：type={event_type} msgtype={msgtype} room={room.room_id[:16]}..."
        )

        # Handle in-room verification events
        # Matrix spec: standalone verification events have type m.key.verification.*
        # But in-room verification REQUEST is sent as m.room.message with msgtype m.key.verification.request
        if event_type and event_type.startswith("m.key.verification."):
            logger.info(f"[EventProcessor] 检测到验证事件：{event_type}")
            await self._handle_in_room_verification(room, event_data)
            return

        # Check for in-room verification request (m.room.message with msgtype m.key.verification.request)
        if event_type == "m.room.message" and msgtype == "m.key.verification.request":
            logger.info(f"[EventProcessor] 检测到房间内验证请求 (msgtype={msgtype})")
            await self._handle_in_room_verification(room, event_data)
            return

        if event_type in ("m.room.message", "m.room.encrypted", "m.sticker"):
            # Parse plaintext message event, encrypted event, or sticker
            event = parse_event(event_data, room.room_id)
            await self._process_message_event(room, event)

    async def _process_message_event(self, room, event):
        """
        Process a message event

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            # Check if message is encrypted
            event_type = event.event_type
            event_content = event.content

            # Handle encrypted messages first
            if event_type == "m.room.encrypted" or event_content.get("algorithm"):
                if self.e2ee_manager:
                    algorithm = event_content.get("algorithm")
                    logger.debug(f"检测到加密事件，算法：{algorithm}")

                    # 尝试解密
                    decrypted = await self.e2ee_manager.decrypt_event(
                        event_content, event.sender, room.room_id
                    )
                    if decrypted:
                        # 替换事件内容为解密后的内容
                        event.content = decrypted.get("content", {})
                        event.event_type = decrypted.get("type", "m.room.message")
                        event.msgtype = event.content.get("msgtype", "")
                        event.body = event.content.get("body", "")
                        logger.debug(
                            f"成功解密消息 (room_id={room.room_id}, event_id={event.event_id}, algorithm={algorithm})"
                        )

                        # Check if decrypted message is a verification event (request or other steps)
                        is_verification = (
                            event.event_type.startswith("m.key.verification.")
                            or event.msgtype == "m.key.verification.request"
                        )

                        if is_verification:
                            # Check if it's from self (same user)
                            if event.sender == self.user_id:
                                # Only process if from a different device
                                from_device = event.content.get("from_device")
                                if (
                                    from_device
                                    and self.e2ee_manager
                                    and from_device == self.e2ee_manager.device_id
                                ):
                                    return  # Ignore own echo

                            logger.info(
                                f"[EventProcessor] 检测到加密的验证事件 (type={event.event_type})"
                            )
                            # Reconstruct event_data for verification handler
                            verification_event = {
                                "type": event.event_type,
                                "sender": event.sender,
                                "event_id": event.event_id,
                                "content": event.content,
                            }
                            await self._handle_in_room_verification(
                                room, verification_event
                            )
                            return
                    else:
                        logger.warning(
                            f"无法解密消息 (room_id={room.room_id}, event_id={event.event_id})"
                        )
                        return
                else:
                    logger.error(f"收到加密消息但 E2EE 未启用 (room_id={room.room_id})")
                    return

            # Ignore messages from self (unless it was a verification request handled above)
            if event.sender == self.user_id:
                # Double check to ensure we don't process own messages
                logger.debug(f"忽略来自自身的消息：{event.event_id}")
                return

            # Filter historical messages: ignore events before startup
            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):  # Allow 1s drift
                logger.debug(
                    f"忽略启动前的历史消息："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            # Message deduplication: check if already processed
            if event.event_id in self._processed_messages:
                logger.debug(f"忽略重复消息：{event.event_id}")
                return

            # Record processed message ID
            self._processed_messages.add(event.event_id)

            # Limit cache size to prevent memory leak
            if len(self._processed_messages) > self._max_processed_messages:
                # Remove oldest half of message IDs (simple FIFO strategy)
                old_messages = list(self._processed_messages)[
                    : self._max_processed_messages // 2
                ]
                for msg_id in old_messages:
                    self._processed_messages.discard(msg_id)

            # Call message callback
            if self.on_message:
                await self.on_message(room, event)

                # Send read receipt after successful processing
                try:
                    await self.client.send_read_receipt(room.room_id, event.event_id)
                    logger.debug(f"已发送事件 {event.event_id} 的已读回执")
                except Exception as e:
                    logger.debug(f"发送已读回执失败：{e}")

        except Exception as e:
            logger.error(f"处理消息事件时出错：{e}")

    async def _handle_in_room_verification(self, room, event_data: dict):
        """
        Handle in-room verification events (m.key.verification.*)

        Args:
            room: Room object
            event_data: Event data
        """
        event_type = event_data.get("type")
        sender = event_data.get("sender")
        content = event_data.get("content", {})
        event_id = event_data.get("event_id")

        # Ignore events from self, UNLESS it's from a different device (verification request)
        if sender == self.user_id:
            from_device = content.get("from_device")
            # For events that don't have from_device (like cancel, done, mac, key),
            # we need to check if we have a matching session where we're the responder
            if not from_device:
                # For cancel/done events from self without from_device, it's likely our own echo
                # Only ignore if we don't have an active session as a responder
                if event_type in (
                    "m.key.verification.cancel",
                    "m.key.verification.done",
                ):
                    logger.debug(f"忽略来自自身的验证事件：{event_type} (可能是回声)")
                    return
            elif self.e2ee_manager and from_device == self.e2ee_manager.device_id:
                # from_device matches our device_id, definitely our own echo
                return
            # If from_device is different, proceed (it's from another session of the same user)

        logger.info(f"收到房间内验证事件：{event_type} from {sender}")

        if self.e2ee_manager:
            try:
                # Forward to E2EE manager with room_id for in-room response
                await self.e2ee_manager.handle_in_room_verification_event(
                    event_type=event_type,
                    sender=sender,
                    content=content,
                    room_id=room.room_id,
                    event_id=event_id,
                )
            except Exception as e:
                logger.error(f"处理房间内验证事件失败：{e}")
        else:
            logger.warning("E2EE 未启用，忽略房间内验证事件")

    async def process_to_device_events(self, events: list):
        """
        Process to-device events

        Args:
            events: List of to-device events
        """
        for event in events:
            event_type = event.get("type")
            sender = event.get("sender")
            content = event.get("content", {})

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
            if event_type == "m.room_key":
                if self.e2ee_manager:
                    try:
                        sender_key = content.get("sender_key", "")
                        # 如果是加密的，需要先解密
                        if "ciphertext" in content:
                            decrypted = await self.e2ee_manager.decrypt_event(
                                content, sender, ""
                            )
                            if decrypted:
                                await self.e2ee_manager.handle_room_key(
                                    decrypted, sender_key
                                )
                        else:
                            await self.e2ee_manager.handle_room_key(content, sender_key)
                    except Exception as e:
                        logger.error(f"处理 m.room_key 事件失败：{e}")
                else:
                    logger.debug("E2EE 未启用，忽略 m.room_key 事件")
                continue

            # 处理 m.room.encrypted to_device 消息 (通常包含 m.room_key)
            if event_type == "m.room.encrypted":
                if self.e2ee_manager:
                    try:
                        decrypted = await self.e2ee_manager.decrypt_event(
                            content, sender, ""
                        )
                        if decrypted:
                            inner_type = decrypted.get("type")
                            inner_content = decrypted.get("content", decrypted)
                            if inner_type == "m.room_key":
                                sender_key = content.get("sender_key", "")
                                await self.e2ee_manager.handle_room_key(
                                    inner_content, sender_key
                                )
                                logger.debug("成功处理加密的 m.room_key 事件")
                            elif inner_type == "m.forwarded_room_key":
                                sender_key = content.get("sender_key", "")
                                await self.e2ee_manager.handle_room_key(
                                    inner_content, sender_key
                                )
                                logger.debug("成功处理加密的 m.forwarded_room_key 事件")
                            else:
                                logger.debug(
                                    f"收到未知的加密 to_device 事件类型：{inner_type}"
                                )
                    except Exception as e:
                        logger.error(f"处理加密 to_device 事件失败：{e}")
                continue

            # 处理 m.forwarded_room_key 事件 (转发的 Megolm 密钥)
            if event_type == "m.forwarded_room_key":
                if self.e2ee_manager:
                    try:
                        sender_key = content.get("sender_key", "")
                        # 直接处理转发的密钥（格式与 m.room_key 相同）
                        await self.e2ee_manager.handle_room_key(content, sender_key)
                        logger.info(
                            f"成功处理转发的房间密钥：{content.get('session_id', '')[:8]}..."
                        )
                    except Exception as e:
                        logger.error(f"处理 m.forwarded_room_key 事件失败：{e}")
                continue

            # 处理 m.room_key_request 事件 (来自其他设备的密钥请求)
            if event_type == "m.room_key_request":
                if self.e2ee_manager:
                    try:
                        action = content.get("action", "")
                        requesting_device_id = content.get("requesting_device_id", "")
                        body = content.get("body", {})

                        if action == "request":
                            # 跳过自己设备发出的请求
                            if (
                                self.e2ee_manager
                                and requesting_device_id == self.e2ee_manager.device_id
                            ):
                                logger.debug("忽略来自自己设备的密钥请求")
                                continue

                            room_id = body.get("room_id", "")
                            session_id = body.get("session_id", "")
                            sender_key = body.get("sender_key", "")

                            logger.info(
                                f"收到密钥请求：来自设备 {requesting_device_id}，"
                                f"room={room_id[:16]}..., session={session_id[:8]}..."
                            )

                            # 调用 E2EE 管理器响应密钥请求
                            await self.e2ee_manager.respond_to_key_request(
                                sender=sender,
                                requesting_device_id=requesting_device_id,
                                room_id=room_id,
                                session_id=session_id,
                                sender_key=sender_key,
                            )
                        elif action == "request_cancellation":
                            logger.debug(
                                f"密钥请求已取消：device={requesting_device_id}"
                            )
                    except Exception as e:
                        logger.error(f"处理 m.room_key_request 事件失败：{e}")
                continue

            # Log other event types
            logger.debug(f"收到设备间事件：{event_type} 来自 {sender}")

    def clear_processed_messages(self):
        """Clear the processed messages cache"""
        self._processed_messages.clear()

    def get_processed_message_count(self) -> int:
        """Get the number of processed messages in cache"""
        return len(self._processed_messages)
