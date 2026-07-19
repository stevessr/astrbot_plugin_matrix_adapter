"""
Matrix Event Processor
Handles processing of Matrix events (messages, etc.)
"""

import asyncio
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from astrbot.api import logger

from ..constants import (
    MAX_PROCESSED_MESSAGES_1000,
    TIMESTAMP_BUFFER_MS_1000,
)
from ..plugin_config import get_plugin_config
from ..utils import parse_bool
from .event_processor_members import MatrixEventProcessorMembers
from .event_processor_streams import MatrixEventProcessorStreams

if TYPE_CHECKING:
    from ..e2ee import E2EEManager


VISIBLE_ROOM_STATE_EVENT_TYPES = frozenset(
    {
        "m.room.name",
        "m.room.topic",
        "m.room.avatar",
        "m.room.create",
        "m.room.encryption",
        "m.room.server_acl",
        "m.room.tombstone",
        "m.room.power_levels",
        "m.room.join_rules",
        "m.room.history_visibility",
        "m.room.guest_access",
        "m.room.canonical_alias",
        "m.room.aliases",
        "m.room.pinned_events",
        "m.room.third_party_invite",
        "m.space.child",
        "m.space.parent",
    }
)

LIVE_MESSAGING_STATE_EVENT_TYPES = frozenset(
    {
        "m.room.live_messaging",
        "org.matrix.msc4357.live_messaging",
    }
)


def _is_room_state_event_type(event_type: str) -> bool:
    return (
        isinstance(event_type, str)
        and bool(event_type)
        and (
            event_type.startswith(("m.room.", "m.space."))
            or event_type in LIVE_MESSAGING_STATE_EVENT_TYPES
        )
    )


class MatrixEventProcessor(MatrixEventProcessorStreams, MatrixEventProcessorMembers):
    """
    Processes Matrix events
    """

    def __init__(
        self,
        client,
        user_id: str,
        startup_ts: int,
        call_event_config=None,
    ):
        """
        Initialize event processor

        Args:
            client: Matrix HTTP client
            user_id: Bot's user ID
            startup_ts: Startup timestamp (milliseconds) for filtering historical messages
            call_event_config: Optional CallEventConfig controlling whether VoIP /
                MatrixRTC (live) call events are surfaced as system messages
        """
        self.client = client
        self.user_id = user_id
        self.startup_ts = startup_ts
        self.call_event_config = call_event_config
        self.storage_backend_config = get_plugin_config().storage_backend_config

        # Message deduplication
        self._processed_messages: OrderedDict[str, None] = OrderedDict()
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
        self._init_member_storage()

    def set_message_callback(self, callback: Callable):
        """
        Set callback for processed messages

        Args:
            callback: Async function(room, event) -> None
        """
        self.on_message = callback

    def _is_message_processed(self, event_id: str | None) -> bool:
        if not event_id:
            return False
        return event_id in self._processed_messages

    def _mark_message_processed(self, event_id: str | None) -> None:
        if not event_id:
            return
        self._processed_messages[event_id] = None
        self._processed_messages.move_to_end(event_id, last=True)
        while len(self._processed_messages) > self._max_processed_messages:
            self._processed_messages.popitem(last=False)

    _parse_bool_like = staticmethod(parse_bool)

    async def _persist_room_state(self, room) -> None:
        """将房间状态/成员数据持久化到存储后端。"""
        await asyncio.to_thread(
            self.room_member_store.upsert,
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

    def _apply_room_state_event(self, room, event_data: dict) -> None:
        event_type = event_data.get("type", "")
        if not _is_room_state_event_type(event_type):
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
                if content:
                    room.space_children[state_key] = content
                else:
                    room.space_children.pop(state_key, None)
            case "m.space.parent":
                if content:
                    room.space_parents[state_key] = content
                else:
                    room.space_parents.pop(state_key, None)
            case "m.room.third_party_invite":
                if content:
                    room.third_party_invites[state_key] = content
                else:
                    room.third_party_invites.pop(state_key, None)
            case _ if event_type in LIVE_MESSAGING_STATE_EVENT_TYPES:
                enabled = content.get("enabled")
                if isinstance(enabled, bool):
                    room.live_messaging_enabled = enabled
                elif enabled is None:
                    room.live_messaging_enabled = None
                else:
                    room.live_messaging_enabled = bool(enabled)
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
                            room.is_direct = self._parse_bool_like(
                                content.get("is_direct"),
                                False,
                            )

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
                await asyncio.to_thread(
                    self.room_member_store.upsert,
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                )

                # Persist individual user profiles to storage
                for user_id, display_name in room.members.items():
                    avatar_url = room.member_avatars.get(user_id)
                    await asyncio.to_thread(
                        self.user_store.upsert,
                        user_id,
                        display_name,
                        avatar_url,
                    )

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
            elif _is_room_state_event_type(event.get("type", "")):
                self._apply_room_state_event(room, event)

        # Persist room state/members after initial state processing
        await self._persist_room_state(room)

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
        from ..call_events import is_call_event_type
        from ..client.event_types import parse_event

        event_type = event_data.get("type", "")
        content = event_data.get("content", {})
        msgtype = content.get("msgtype", "")

        # Handle membership updates to keep profile cache fresh
        if event_type == "m.room.member":
            await self._handle_member_event(room, event_data)
            event = parse_event(event_data, room.room_id)
            await self._process_member_event(room, event)
            return

        # Handle other room state updates
        if _is_room_state_event_type(event_type) and "state_key" in event_data:
            self._apply_room_state_event(room, event_data)
            await self._persist_room_state(room)

            # Process notable state changes as system events for user visibility
            if event_type in VISIBLE_ROOM_STATE_EVENT_TYPES:
                event = parse_event(event_data, room.room_id)
                await self._process_room_state_event(room, event)

            return

        # Handle in-room verification events
        # Matrix spec: standalone verification events have type m.key.verification.*
        # But in-room verification REQUEST is sent as m.room.message with msgtype m.key.verification.request
        if event_type and event_type.startswith("m.key.verification."):
            await self._handle_in_room_verification(room, event_data)
            return

        # Handle VoIP / MatrixRTC (live) call events. These are surfaced as
        # system events when enabled via config; otherwise ignored (the bot
        # cannot participate in WebRTC media directly).
        if event_type and is_call_event_type(event_type):
            await self._process_call_event(room, event_data)
            return

        # Check for in-room verification request (m.room.message with msgtype m.key.verification.request)
        if event_type == "m.room.message" and msgtype == "m.key.verification.request":
            await self._handle_in_room_verification(room, event_data)
            return

        if event_type in (
            "m.room.message",
            "m.room.encrypted",
            "m.room.redaction",
            "m.sticker",
            "m.reaction",
            "m.location",
            "m.poll.start",
            "m.poll.response",
            "m.poll.end",
            "org.matrix.msc3488.location",
            "org.matrix.msc3381.poll.start",
            "org.matrix.msc3381.poll.response",
            "org.matrix.msc3381.poll.end",
            "m.beacon",
            "m.beacon_info",
            "org.matrix.msc3672.beacon",
            "org.matrix.msc3672.beacon_info",
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
            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"成员事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

            if sender == self.user_id:
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

            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复成员事件：{event.event_id}")
                return

            self._mark_message_processed(event.event_id)

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
            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"状态事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

            # Don't process events from self
            if sender == self.user_id:
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
            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复状态事件：{event.event_id}")
                return

            self._mark_message_processed(event.event_id)

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
        except Exception as e:
            logger.error(f"处理状态事件时出错：{e}")

    async def _process_call_event(self, room, event_data: dict):
        """
        Process VoIP / MatrixRTC (live) call events as system events.

        Surfacing is gated by the per-adapter call_event_config. Events from
        self, historical events (before startup) and duplicates are filtered
        out, mirroring room state event handling.

        Args:
            room: Room object
            event_data: Raw event data
        """
        try:
            from ..call_events import should_surface_call_event
            from ..client.event_types import parse_event

            event_type = event_data.get("type", "")
            config = self.call_event_config
            if config is None or not should_surface_call_event(event_type, config):
                return

            event = parse_event(event_data, room.room_id)

            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"通话事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

            # Don't process events from self
            if sender == self.user_id:
                logger.debug(f"忽略来自自身的通话事件：{event.event_id}")
                return

            # Check timestamp to filter historical events
            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):
                logger.debug(
                    f"忽略启动前的通话事件："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            # Check for duplicates
            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复通话事件：{event.event_id}")
                return

            self._mark_message_processed(event.event_id)

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
        except Exception as e:
            logger.error(f"处理通话事件时出错：{e}")

    async def _process_message_event(self, room, event):
        """
        Process a message event

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"room timeline 事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

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
                        event_content, sender, room.room_id
                    )
                    if decrypted:
                        decrypted_content = dict(decrypted.get("content", {}) or {})
                        # Relation metadata for encrypted relation/verification
                        # events is often carried in the cleartext envelope.  Keep
                        # it before reparsing so edits, threads, live-message final
                        # updates, and verification commitment calculations all see
                        # the same m.relates_to data as plaintext events.
                        cleartext_relates_to = event_content.get("m.relates_to")
                        if (
                            cleartext_relates_to
                            and "m.relates_to" not in decrypted_content
                        ):
                            decrypted_content["m.relates_to"] = cleartext_relates_to

                        # 替换事件内容为解密后的内容
                        event.content = decrypted_content
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
                            if sender == self.user_id:
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
                            if cleartext_relates_to:
                                event.content["m.relates_to"] = cleartext_relates_to

                            # Reconstruct event_data for verification handler
                            verification_event = {
                                "type": event.event_type,
                                "sender": sender,
                                "event_id": event.event_id,
                                "content": event.content,
                            }
                            await self._handle_in_room_verification(
                                room, verification_event
                            )
                            return

                        from ..client.event_types import parse_event

                        event = parse_event(
                            {
                                "type": event.event_type,
                                "event_id": event.event_id,
                                "sender": sender,
                                "origin_server_ts": getattr(
                                    event, "origin_server_ts", 0
                                ),
                                "content": event.content,
                                "unsigned": getattr(event, "unsigned", None),
                            },
                            room.room_id,
                        )
                        event_type = event.event_type
                        event_content = event.content
                    else:
                        logger.warning(
                            f"无法解密消息 (room_id={room.room_id}, event_id={event.event_id})"
                        )
                        return
                else:
                    logger.error(f"收到加密消息但 E2EE 未启用 (room_id={room.room_id})")
                    return

            # Ignore messages from self (unless it was a verification request handled above)
            if sender == self.user_id:
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
            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复消息：{event.event_id}")
                return

            self._mark_message_processed(event.event_id)

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
        if not isinstance(sender, str) or not sender:
            logger.debug(
                f"房间内验证事件缺少 sender：type={event_type}, event_id={event_id}"
            )
            return

        if not event_type or not event_id:
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
            logger.debug(f"收到 {len(events)} 个 to_device 事件")

        # Import available room keys before answering sibling-device requests,
        # then handle those requests before unrelated verification traffic.
        key_event_types = {
            "m.room_key",
            "m.forwarded_room_key",
            "m.room.encrypted",
        }
        events = sorted(
            events,
            key=lambda event: (
                0
                if isinstance(event, dict) and event.get("type") in key_event_types
                else (
                    1
                    if isinstance(event, dict)
                    and event.get("type") == "m.room_key_request"
                    and (event.get("content") or {}).get("action") == "request"
                    else 2
                )
            ),
        )

        for event in events:
            event_type = event.get("type")
            sender = event.get("sender")
            if not isinstance(sender, str) or not sender:
                logger.warning(f"to_device 事件缺少 sender，跳过：type={event_type}")
                continue
            content = event.get("content", {})

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
                                logger.debug(f"收到加密的验证事件：{inner_type}")
                                await self.e2ee_manager.handle_verification_event(
                                    inner_type, sender, inner_content
                                )
                            elif inner_type == "m.secret.send":
                                logger.debug("收到加密的 m.secret.send 事件")
                                await self.e2ee_manager.handle_secret_send(
                                    sender, inner_content
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
            if event_type == "m.forwarded_room_key":
                if self.e2ee_manager:
                    try:
                        sender_key = content.get("sender_key", "")
                        # 直接处理转发的密钥（格式与 m.room_key 相同）
                        await self.e2ee_manager.handle_room_key(content, sender_key)
                        logger.debug(
                            "成功处理转发的房间密钥："
                            f"{(content.get('session_id') or '')[:8]}..."
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

                            if (
                                body.get("algorithm") != "m.megolm.v1.aes-sha2"
                                or not requesting_device_id
                                or not room_id
                                or not session_id
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
