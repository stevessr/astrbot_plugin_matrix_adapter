"""VoIP and MatrixRTC call event processing handlers."""

from astrbot.api import logger

from ....client.event_types import parse_event
from ....constants import TIMESTAMP_BUFFER_MS_1000


class MatrixEventProcessorCallsMixin:
    """Process surfaced VoIP and MatrixRTC call events."""

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
            from ....events.call import should_surface_call_event

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
