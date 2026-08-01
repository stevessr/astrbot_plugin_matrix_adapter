"""
Matrix Event Processor - States Mixin
Handles room state events, member events, call events, and in-room verification.
"""

import asyncio

from astrbot.api import logger

from ...client.event_types import parse_event
from ...constants import (
    M_ROOM_ALIASES,
    M_ROOM_AVATAR,
    M_ROOM_CANONICAL_ALIAS,
    M_ROOM_CREATE,
    M_ROOM_ENCRYPTION,
    M_ROOM_GUEST_ACCESS,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_JOIN_RULES,
    M_ROOM_LIVE_MESSAGING,
    M_ROOM_NAME,
    M_ROOM_PINNED_EVENTS,
    M_ROOM_POWER_LEVELS,
    M_ROOM_SERVER_ACL,
    M_ROOM_THIRD_PARTY_INVITE,
    M_ROOM_TOMBSTONE,
    M_ROOM_TOPIC,
    M_SPACE_CHILD,
    M_SPACE_PARENT,
    MSC4357_LIVE_MESSAGING_STATE,
    TIMESTAMP_BUFFER_MS_1000,
)

VISIBLE_ROOM_STATE_EVENT_TYPES = frozenset(
    {
        M_ROOM_NAME,
        M_ROOM_TOPIC,
        M_ROOM_AVATAR,
        M_ROOM_CREATE,
        M_ROOM_ENCRYPTION,
        M_ROOM_SERVER_ACL,
        M_ROOM_TOMBSTONE,
        M_ROOM_POWER_LEVELS,
        M_ROOM_JOIN_RULES,
        M_ROOM_HISTORY_VISIBILITY,
        M_ROOM_GUEST_ACCESS,
        M_ROOM_CANONICAL_ALIAS,
        M_ROOM_ALIASES,
        M_ROOM_PINNED_EVENTS,
        M_ROOM_THIRD_PARTY_INVITE,
        M_SPACE_CHILD,
        M_SPACE_PARENT,
    }
)

LIVE_MESSAGING_STATE_EVENT_TYPES = frozenset(
    {
        M_ROOM_LIVE_MESSAGING,
        MSC4357_LIVE_MESSAGING_STATE,
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


class MatrixEventProcessorStatesMixin:
    """Mixin for room state event processing."""

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

        if event_type == M_ROOM_NAME:
            room.display_name = content.get("name", "") or ""
        elif event_type == M_ROOM_TOPIC:
            room.topic = content.get("topic", "") or ""
        elif event_type == M_ROOM_AVATAR:
            room.avatar_url = content.get("url") or None
        elif event_type == M_ROOM_JOIN_RULES:
            room.join_rules = content
        elif event_type == M_ROOM_POWER_LEVELS:
            room.power_levels = content
        elif event_type == M_ROOM_HISTORY_VISIBILITY:
            room.history_visibility = content.get("history_visibility")
        elif event_type == M_ROOM_GUEST_ACCESS:
            room.guest_access = content.get("guest_access")
        elif event_type == M_ROOM_CANONICAL_ALIAS:
            room.canonical_alias = content.get("alias")
            alt_aliases = content.get("alt_aliases") or []
            if isinstance(alt_aliases, list):
                room.room_aliases = alt_aliases
        elif event_type == M_ROOM_ALIASES:
            aliases = content.get("aliases") or []
            if isinstance(aliases, list):
                room.room_aliases = aliases
        elif event_type == M_ROOM_ENCRYPTION:
            room.encryption = content
        elif event_type == M_ROOM_CREATE:
            room.create = content
        elif event_type == M_ROOM_TOMBSTONE:
            room.tombstone = content
        elif event_type == M_ROOM_PINNED_EVENTS:
            pinned = content.get("pinned") or []
            if isinstance(pinned, list):
                room.pinned_events = pinned
        elif event_type == M_SPACE_CHILD:
            if content:
                room.space_children[state_key] = content
            else:
                room.space_children.pop(state_key, None)
        elif event_type == M_SPACE_PARENT:
            if content:
                room.space_parents[state_key] = content
            else:
                room.space_parents.pop(state_key, None)
        elif event_type == M_ROOM_THIRD_PARTY_INVITE:
            if content:
                room.third_party_invites[state_key] = content
            else:
                room.third_party_invites.pop(state_key, None)
        elif event_type in LIVE_MESSAGING_STATE_EVENT_TYPES:
            enabled = content.get("enabled")
            if isinstance(enabled, bool):
                room.live_messaging_enabled = enabled
            else:
                # MSC4357 defines ``enabled`` as a JSON boolean. Invalid or
                # absent values behave like no usable room-level override.
                room.live_messaging_enabled = None

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

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
                self._mark_message_processed(event.event_id)
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

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
                self._mark_message_processed(event.event_id)
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
            from ...call_events import should_surface_call_event

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

            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
                self._mark_message_processed(event.event_id)
        except Exception as e:
            logger.error(f"处理通话事件时出错：{e}")

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
