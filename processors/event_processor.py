"""
Matrix Event Processor
Handles processing of Matrix events (messages, etc.)
"""

from collections.abc import Callable
from typing import TYPE_CHECKING

from astrbot.api import logger

from ..constants import MAX_PROCESSED_MESSAGES_1000, TIMESTAMP_BUFFER_MS_1000
from ..storage_backend import StorageBackendConfig
from .event_processor_members import MatrixEventProcessorMembers
from .event_processor_streams import MatrixEventProcessorStreams

if TYPE_CHECKING:
    from ..e2ee import E2EEManager


class MatrixEventProcessor(MatrixEventProcessorStreams, MatrixEventProcessorMembers):
    """
    Processes Matrix events
    """

    def __init__(
        self,
        client,
        user_id: str,
        startup_ts: int,
        storage_backend_config: StorageBackendConfig | None = None,
    ):
        """
        Initialize event processor

        Args:
            client: Matrix HTTP client
            user_id: Bot's user ID
            startup_ts: Startup timestamp (milliseconds) for filtering historical messages
            storage_backend_config: 运行时固定存储后端配置
        """
        self.client = client
        self.user_id = user_id
        self.startup_ts = startup_ts
        self.storage_backend_config = storage_backend_config

        # Message deduplication
        self._processed_messages: set[str] = set()
        self._max_processed_messages = MAX_PROCESSED_MESSAGES_1000

        # Event callbacks
        self.on_message: Callable | None = None

        # E2EE manager (set by adapter if E2EE is enabled)
        self.e2ee_manager: E2EEManager | None = None

        # Sync stream caches
        self.global_account_data: dict[str, dict] = {}
        self.room_account_data: dict[str, dict[str, dict]] = {}
        self.presence: dict[str, dict] = {}
        self.typing: dict[str, set[str]] = {}
        self.receipts: dict[str, dict] = {}
        self.device_lists: dict[str, set[str]] = {"changed": set(), "left": set()}
        self.one_time_keys_count: dict[str, int] = {}
        self._init_member_storage(storage_backend_config=self.storage_backend_config)

    def set_message_callback(self, callback: Callable):
        """
        Set callback for processed messages

        Args:
            callback: Async function(room, event) -> None
        """
        self.on_message = callback

    def _apply_room_state_event(self, room, event_data: dict) -> None:
        event_type = event_data.get("type", "")
        if not (event_type.startswith("m.room.") or event_type.startswith("m.space.")):
            return
        state_key = event_data.get("state_key", "")
        content = event_data.get("content", {}) or {}

        room.state_events.setdefault(event_type, {})[state_key] = content

        match event_type:
            case "m.room.name":
                room.display_name = content.get("name", "") or ""
            case "m.room.topic":
                room.topic = content.get("topic", "") or ""
            case "m.room.avatar":
                room.avatar_url = content.get("url") or None
            case "m.room.join_rules":
                room.join_rules = content
            case "m.room.power_levels":
                room.power_levels = content
            case "m.room.history_visibility":
                room.history_visibility = content.get("history_visibility")
            case "m.room.guest_access":
                room.guest_access = content.get("guest_access")
            case "m.room.canonical_alias":
                room.canonical_alias = content.get("alias")
                alt_aliases = content.get("alt_aliases") or []
                if isinstance(alt_aliases, list):
                    room.room_aliases = alt_aliases
            case "m.room.aliases":
                aliases = content.get("aliases") or []
                if isinstance(aliases, list):
                    room.room_aliases = aliases
            case "m.room.encryption":
                room.encryption = content
            case "m.room.create":
                room.create = content
            case "m.room.tombstone":
                room.tombstone = content
            case "m.room.pinned_events":
                pinned = content.get("pinned") or []
                if isinstance(pinned, list):
                    room.pinned_events = pinned
            case "m.space.child":
                room.space_children[state_key] = content
            case "m.space.parent":
                room.space_parents[state_key] = content
            case "m.room.third_party_invite":
                room.third_party_invites[state_key] = content
            case _:
                return

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

        # Flag direct rooms from account data (m.direct)
        direct_data = self.global_account_data.get("m.direct")
        if isinstance(direct_data, dict):
            # Check if room is in m.direct (explicitly marked as DM)
            room.is_direct = any(
                isinstance(room_ids, list) and room_id in room_ids
                for room_ids in direct_data.values()
            )

        # Try to load from storage first to avoid unnecessary API calls
        loaded_from_storage = await self.load_room_members_from_storage(room)

        if loaded_from_storage:
            logger.debug(
                f"从缓存加载房间 {room_id} 成员数据：{room.member_count} 个成员"
            )
        else:
            # Fetch complete member list from API to ensure accuracy
            try:
                members_response = await self.client.get_room_members(room_id)
                chunk = members_response.get("chunk", [])

                # Process member events from API response
                for event in chunk:
                    if event.get("type") == "m.room.member":
                        user_id = event.get("state_key")
                        content = event.get("content", {})
                        membership = content.get("membership")

                        # Check for is_direct flag in member events
                        if (
                            user_id == self.user_id
                            and room.is_direct is None
                            and "is_direct" in content
                        ):
                            room.is_direct = bool(content.get("is_direct"))

                        # Only count joined members
                        if membership == "join":
                            display_name = content.get("displayname", user_id)
                            room.members[user_id] = display_name
                            avatar_url = content.get("avatar_url")
                            if avatar_url:
                                room.member_avatars[user_id] = avatar_url

                # Set member count from complete member list
                room.member_count = len(room.members)
                logger.info(
                    f"房间 {room_id} 成员列表（从 API）: "
                    f"总人数={room.member_count}, "
                    f"成员列表={list(room.members.keys())}"
                )

                # Persist room member data to storage
                self.room_member_store.upsert(
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                )

                # Persist individual user profiles to storage
                for user_id, display_name in room.members.items():
                    avatar_url = room.member_avatars.get(user_id)
                    self.user_store.upsert(user_id, display_name, avatar_url)

            except Exception as e:
                logger.error(f"获取房间 {room_id} 成员列表失败：{e}")
                # Final fallback: use /sync summary counts
                summary = room_data.get("summary", {})
                joined_count = summary.get("joined_member_count")
                invited_count = summary.get("invited_member_count")
                if isinstance(joined_count, int):
                    room.member_count = joined_count + (
                        invited_count if isinstance(invited_count, int) else 0
                    )
                    logger.warning(
                        f"房间 {room_id} 使用备用方案（summary）: "
                        f"joined={joined_count}, invited={invited_count}, "
                        f"total={room.member_count}"
                    )

        # Process state events to get room information (for other state types)
        state_events = room_data.get("state", {}).get("events", [])
        for event in state_events:
            if event.get("type") == "m.room.member":
                user_id = event.get("state_key")
                content = event.get("content", {})
                if content.get("membership") == "join":
                    display_name = content.get("displayname", user_id)
                    room.members[user_id] = display_name
                    avatar_url = content.get("avatar_url")
                    if avatar_url:
                        room.member_avatars[user_id] = avatar_url
            elif event.get("type", "").startswith(("m.room.", "m.space.")):
                self._apply_room_state_event(room, event)

        # Persist room state/members after initial state processing
        self.room_member_store.upsert(
            room_id=room.room_id,
            members=room.members,
            member_avatars=room.member_avatars,
            member_count=room.member_count,
            is_direct=room.is_direct,
            room_name=room.display_name,
            topic=room.topic,
            avatar_url=room.avatar_url,
            join_rules=room.join_rules,
            power_levels=room.power_levels,
            history_visibility=room.history_visibility,
            guest_access=room.guest_access,
            canonical_alias=room.canonical_alias,
            room_aliases=room.room_aliases,
            encryption=room.encryption,
            create=room.create,
            tombstone=room.tombstone,
            pinned_events=room.pinned_events,
            space_children=room.space_children,
            space_parents=room.space_parents,
            third_party_invites=room.third_party_invites,
            state_events=room.state_events,
        )

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

        # Handle membership updates to keep profile cache fresh
        if event_type == "m.room.member":
            await self._handle_member_event(room, event_data)
            event = parse_event(event_data, room.room_id)
            await self._process_member_event(room, event)
            return

        # Handle other room state updates
        if (
            event_type
            and event_type.startswith(("m.room.", "m.space."))
            and "state_key" in event_data
        ):
            self._apply_room_state_event(room, event_data)
            self.room_member_store.upsert(
                room_id=room.room_id,
                members=room.members,
                member_avatars=room.member_avatars,
                member_count=room.member_count,
                is_direct=room.is_direct,
                room_name=room.display_name,
                topic=room.topic,
                avatar_url=room.avatar_url,
                join_rules=room.join_rules,
                power_levels=room.power_levels,
                history_visibility=room.history_visibility,
                guest_access=room.guest_access,
                canonical_alias=room.canonical_alias,
                room_aliases=room.room_aliases,
                encryption=room.encryption,
                create=room.create,
                tombstone=room.tombstone,
                pinned_events=room.pinned_events,
                space_children=room.space_children,
                space_parents=room.space_parents,
                third_party_invites=room.third_party_invites,
                state_events=room.state_events,
            )

            # Process notable state changes as system events for user visibility
            if event_type in (
                "m.room.name",
                "m.room.topic",
                "m.room.encryption",
                "m.room.tombstone",
            ):
                event = parse_event(event_data, room.room_id)
                await self._process_room_state_event(room, event)

            return

        # Handle in-room verification events
        # Matrix spec: standalone verification events have type m.key.verification.*
        # But in-room verification REQUEST is sent as m.room.message with msgtype m.key.verification.request
        if event_type and event_type.startswith("m.key.verification."):
            await self._handle_in_room_verification(room, event_data)
            return

        # Skip redaction events (no visible output)
        if event_type == "m.room.redaction":
            return

        # Skip VoIP call events (framework does not support m.call.* yet)
        if event_type and event_type.startswith("m.call."):
            return

        # Check for in-room verification request (m.room.message with msgtype m.key.verification.request)
        if event_type == "m.room.message" and msgtype == "m.key.verification.request":
            await self._handle_in_room_verification(room, event_data)
            return

        if event_type in (
            "m.room.message",
            "m.room.encrypted",
            "m.sticker",
            "m.reaction",
            "m.poll.response",
            "m.poll.end",
            "org.matrix.msc3381.poll.response",
            "org.matrix.msc3381.poll.end",
        ):
            # Parse plaintext message event, encrypted event, sticker, or poll event
            event = parse_event(event_data, room.room_id)
            await self._process_message_event(room, event)

    async def _process_member_event(self, room, event):
        """
        Process membership/system events as OtherMessage.

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            if event.sender == self.user_id:
                logger.debug(f"忽略来自自身的成员事件：{event.event_id}")
                return

            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):
                logger.debug(
                    f"忽略启动前的成员事件："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            if event.event_id in self._processed_messages:
                logger.debug(f"忽略重复成员事件：{event.event_id}")
                return

            self._processed_messages.add(event.event_id)
            if len(self._processed_messages) > self._max_processed_messages:
                old_messages = list(self._processed_messages)[
                    : self._max_processed_messages // 2
                ]
                for msg_id in old_messages:
                    self._processed_messages.discard(msg_id)

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
        except Exception as e:
            logger.error(f"处理成员事件时出错：{e}")

    async def _process_room_state_event(self, room, event):
        """
        Process room state change events (name, topic, encryption, etc.)
        as system events for user visibility.

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            # Don't process events from self
            if event.sender == self.user_id:
                logger.debug(f"忽略来自自身的状态事件：{event.event_id}")
                return

            # Check timestamp to filter historical events
            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):
                logger.debug(
                    f"忽略启动前的状态事件："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            # Check for duplicates
            if event.event_id in self._processed_messages:
                logger.debug(f"忽略重复状态事件：{event.event_id}")
                return

            self._processed_messages.add(event.event_id)
            if len(self._processed_messages) > self._max_processed_messages:
                old_messages = list(self._processed_messages)[
                    : self._max_processed_messages // 2
                ]
                for msg_id in old_messages:
                    self._processed_messages.discard(msg_id)

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
        except Exception as e:
            logger.error(f"处理状态事件时出错：{e}")

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

                            logger.debug(
                                f"[EventProcessor] 检测到加密的验证事件 (type={event.event_type})"
                            )

                            # CRITICAL: For encrypted in-room verification events,
                            # m.relates_to is in the CLEARTEXT portion of the encrypted event
                            # (event_content), not in the decrypted payload.
                            # We need to copy it to the decrypted content for commitment calculation.
                            cleartext_relates_to = event_content.get("m.relates_to")
                            if cleartext_relates_to:
                                event.content["m.relates_to"] = cleartext_relates_to

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
                await self._persist_interacted_user(room, event)
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

        # 验证必需字段
        if not event_type or not sender or not event_id:
            logger.debug(
                f"房间内验证事件缺少必需字段：type={event_type}, sender={sender}, event_id={event_id}"
            )
            return

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
                    return
            elif self.e2ee_manager and from_device == self.e2ee_manager.device_id:
                # from_device matches our device_id, definitely our own echo
                return
            # If from_device is different, proceed (it's from another session of the same user)

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
        if events:
            logger.info(f"收到 {len(events)} 个 to_device 事件")

        for event in events:
            event_type = event.get("type")
            sender = event.get("sender")
            content = event.get("content", {})

            logger.info(f"处理 to_device 事件：type={event_type} sender={sender}")

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
                        algorithm = content.get("algorithm", "unknown")
                        sender_key = content.get("sender_key", "")[:16]
                        logger.info(
                            f"收到加密的 to_device 消息：algorithm={algorithm} "
                            f"sender_key={sender_key}..."
                        )

                        decrypted = await self.e2ee_manager.decrypt_event(
                            content, sender, ""
                        )
                        logger.info(f"解密 to_device 结果：{decrypted is not None}")
                        if decrypted:
                            inner_type = decrypted.get("type")
                            inner_content = decrypted.get("content", decrypted)
                            logger.info(f"解密后的事件类型：{inner_type}")
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
                            elif inner_type and inner_type.startswith(
                                "m.key.verification."
                            ):
                                logger.info(f"收到加密的验证事件：{inner_type}")
                                await self.e2ee_manager.handle_verification_event(
                                    inner_type, sender, inner_content
                                )
                            elif inner_type == "m.secret.send":
                                logger.info("收到加密的 m.secret.send 事件")
                                await self.e2ee_manager.handle_secret_send(
                                    sender, inner_content
                                )
                            elif inner_type == "m.dummy":
                                logger.debug("收到 m.dummy 事件，忽略")
                            else:
                                logger.info(
                                    f"收到未知的加密 to_device 事件类型：{inner_type}，内容键：{list(decrypted.keys()) if isinstance(decrypted, dict) else type(decrypted)}"
                                )
                        else:
                            # 解密失败
                            ciphertext_keys = list(content.get("ciphertext", {}).keys())
                            logger.warning(
                                f"解密 to_device 消息失败，ciphertext 目标密钥：{ciphertext_keys}"
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

    def clear_processed_messages(self):
        """Clear the processed messages cache"""
        self._processed_messages.clear()

    def get_processed_message_count(self) -> int:
        """Get the number of processed messages in cache"""
        return len(self._processed_messages)
