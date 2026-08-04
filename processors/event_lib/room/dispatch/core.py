"""
Matrix Event Processor - Room Dispatch Mixin
Handles room event dispatch: process_room_events.
"""

from astrbot.api import logger


class MatrixEventProcessorRoomDispatchCoreMixin:
    """Mixin for room event dispatch."""

    async def process_room_events(self, room_id: str, room_data: dict):
        """
        Process events from a room

        Args:
            room_id: Room ID
            room_data: Room data from sync response
        """
        # Update import: Client event types in ..client.event_types
        from .....client.event_types import MatrixRoom

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
        loaded_from_storage = await self._load_room_members(room_id, room, room_data)

        if loaded_from_storage:
            logger.debug(
                f"从缓存加载房间 {room_id} 成员数据：{room.member_count} 个成员"
            )

        # Process state events to get room information (for other state types)
        state_events = room_data.get("state", {}).get("events", [])
        e2ee_manager = getattr(self, "e2ee_manager", None)
        await self._process_room_state_events(room, state_events, e2ee_manager)

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
