"""Room state event processing for dispatch."""

from astrbot.api import logger

from .....constants import M_ROOM_HISTORY_VISIBILITY, M_ROOM_MEMBER
from ...states import _is_room_state_event_type


class MatrixEventProcessorRoomStateMixin:
    """Apply state-event deltas to the room model."""

    async def _process_room_state_events(self, room, state_events, e2ee_manager):
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
