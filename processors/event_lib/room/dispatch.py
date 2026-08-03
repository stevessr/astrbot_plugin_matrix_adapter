"""
Matrix Event Processor - Room Dispatch Mixin
Handles room event dispatch: process_room_events and _handle_event.
"""

import asyncio

from astrbot.api import logger

from ....constants import (
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    MEMBERSHIP_JOIN,
)
from ..states import _is_room_state_event_type


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
        from ....client.event_types import MatrixRoom

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
