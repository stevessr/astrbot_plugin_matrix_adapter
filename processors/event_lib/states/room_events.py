"""Room state event visibility handlers."""

from astrbot.api import logger

from ....constants import TIMESTAMP_BUFFER_MS_1000


class MatrixEventProcessorRoomStateMixin:
    """Process room state changes for user visibility."""

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
