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

        # Matrix v1.16 / MSC4222: the presence of state_after (even with an
        # empty events list) tells the client that this is the authoritative
        # end-of-timeline state. Keep unstable support for pre-stable servers.
        has_stable_state_after = "state_after" in room_data
        has_unstable_state_after = "org.matrix.msc4222.state_after" in room_data
        uses_state_after = has_stable_state_after or has_unstable_state_after
        if has_stable_state_after:
            state_section = room_data.get("state_after") or {}
        elif has_unstable_state_after:
            state_section = room_data.get("org.matrix.msc4222.state_after") or {}
        else:
            state_section = room_data.get("state") or {}

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

        # Process authoritative room state. Under MSC4222 this is state_after;
        # otherwise retain the legacy pre-timeline `state` behavior.
        state_events = (
            state_section.get("events", []) if isinstance(state_section, dict) else []
        )
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

        # Process timeline events. MSC4222 requires clients to NOT mutate their
        # local current state from timeline state events when state_after is in
        # use; those events may be stale losers of state resolution.
        for event_data in events:
            try:
                if uses_state_after and "state_key" in event_data:
                    continue
                await self._handle_event(room, event_data)
            except Exception as e:
                event_id = event_data.get("event_id", "<unknown>")
                logger.error(f"处理事件 {event_id} 失败：{e}")

        # Re-persist after timeline processing to capture message-derived data
        # and legacy timeline state changes when state_after was not negotiated.
        await self._persist_room_state(room)
