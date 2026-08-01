"""
Matrix Event Processor - Room Dispatch Mixin
Handles room event dispatch: process_room_events and _handle_event.
"""

import asyncio

from astrbot.api import logger

from ...call_events import is_call_event_type
from ...client.event_types import parse_event
from ...constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    M_ROOM_MESSAGE,
    M_ROOM_REDACTION,
    MEMBERSHIP_JOIN,
)
from .states import (
    VISIBLE_ROOM_STATE_EVENT_TYPES,
    _is_room_state_event_type,
)


class MatrixEventProcessorRoomDispatchMixin:
    """Mixin for room event dispatch."""

    async def process_room_events(self, room_id: str, room_data: dict):
        """
        Process events from a room

        Args:
            room_id: Room ID
            room_data: Room data from sync response
        """
        # Update import: Client event types in ..client.event_types
        from ...client.event_types import MatrixRoom

        timeline = room_data.get("timeline", {})
        events = timeline.get("events", [])

        # Build simplified room object
        room = MatrixRoom(room_id=room_id)
        room.timeline_limited = timeline.get("limited") is True

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
                    if event.get("type") == M_ROOM_MEMBER:
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
                        if membership == MEMBERSHIP_JOIN:
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
        e2ee_manager = getattr(self, "e2ee_manager", None)
        for event in state_events:
            if event.get("type") == M_ROOM_MEMBER:
                # State deltas can contain joins/leaves hidden by a limited
                # timeline. Apply the crypto/member transition without
                # rendering it as a timeline system message.
                await self._handle_member_event(room, event)
                if event.get("event_id"):
                    self._mark_message_processed(event["event_id"])
            elif _is_room_state_event_type(event.get("type", "")):
                event_type = event.get("type")
                previous_history_visibility = room.history_visibility
                self._apply_room_state_event(room, event)
                if event_type == M_ROOM_HISTORY_VISIBILITY and e2ee_manager:
                    on_visibility_changed = getattr(
                        e2ee_manager,
                        "on_history_visibility_changed",
                        None,
                    )
                    if callable(on_visibility_changed):
                        try:
                            await on_visibility_changed(
                                room.room_id,
                                previous_history_visibility,
                                room.history_visibility,
                            )
                        except Exception as e:
                            logger.warning(
                                f"Failed to update encrypted-history sharing: {e}"
                            )

        if e2ee_manager and isinstance(room.encryption, dict):
            set_encryption_config = getattr(
                e2ee_manager,
                "set_room_encryption_config",
                None,
            )
            if callable(set_encryption_config):
                set_encryption_config(room.room_id, room.encryption)

        # Persist room state/members after initial state processing
        await self._persist_room_state(room)

        # Process timeline events
        for event_data in events:
            try:
                await self._handle_event(room, event_data)
            except Exception as e:
                event_id = event_data.get("event_id", "<unknown>")
                logger.error(f"处理事件 {event_id} 失败：{e}")

        # Re-persist after timeline processing to capture any state changes
        await self._persist_room_state(room)


    async def _handle_event(self, room, event_data: dict):
        """
        Handle a single event

        Args:
            room: Room object
            event_data: Event data
        """
        event_type = event_data.get("type", "")
        content = event_data.get("content", {})
        msgtype = content.get("msgtype", "")

        # Handle membership updates to keep profile cache fresh
        if event_type == M_ROOM_MEMBER:
            event_id = event_data.get("event_id")
            if event_id and self._is_message_processed(event_id):
                return
            await self._handle_member_event(room, event_data)
            event = parse_event(event_data, room.room_id)
            await self._process_member_event(room, event)
            return

        # Handle other room state updates
        if _is_room_state_event_type(event_type) and "state_key" in event_data:
            previous_history_visibility = getattr(room, "history_visibility", None)
            self._apply_room_state_event(room, event_data)
            e2ee_manager = getattr(self, "e2ee_manager", None)
            if event_type == M_ROOM_HISTORY_VISIBILITY and e2ee_manager:
                on_visibility_changed = getattr(
                    e2ee_manager,
                    "on_history_visibility_changed",
                    None,
                )
                if callable(on_visibility_changed):
                    try:
                        await on_visibility_changed(
                            room.room_id,
                            previous_history_visibility,
                            room.history_visibility,
                        )
                    except Exception as e:
                        logger.warning(f"更新加密历史共享状态失败：{e}")
            elif event_type == M_ROOM_ENCRYPTION and e2ee_manager:
                set_encryption_config = getattr(
                    e2ee_manager,
                    "set_room_encryption_config",
                    None,
                )
                if callable(set_encryption_config):
                    set_encryption_config(room.room_id, room.encryption or {})
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
        if event_type == M_ROOM_MESSAGE and msgtype == "m.key.verification.request":
            await self._handle_in_room_verification(room, event_data)
            return

        # Handle redaction: apply to cached room state
        if event_type == M_ROOM_REDACTION:
            redact_event_id = content.get("redacts", "")
            if redact_event_id and hasattr(room, "state_events"):
                removed = False
                for key in list(room.state_events.keys()):
                    ev = room.state_events.get(key, {})
                    if isinstance(ev, dict) and ev.get("event_id") == redact_event_id:
                        del room.state_events[key]
                        removed = True
                if removed:
                    await self._persist_room_state(room)
            event = parse_event(event_data, room.room_id)
            await self._process_message_event(room, event)
            return

        if event_type in (
            M_ROOM_MESSAGE,
            M_ROOM_ENCRYPTED,
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

