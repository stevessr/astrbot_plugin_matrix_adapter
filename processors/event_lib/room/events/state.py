"""Room state event handling for Matrix room events."""

from astrbot.api import logger

from .....client.event_types import parse_event
from .....constants import M_ROOM_ENCRYPTION, M_ROOM_HISTORY_VISIBILITY
from ...states import VISIBLE_ROOM_STATE_EVENT_TYPES


class MatrixEventProcessorRoomStateUpdateMixin:
    """Handle other room state updates."""

    async def _handle_room_state_update(
        self, room, event_data: dict, event_type: str
    ) -> bool:
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

        return True
