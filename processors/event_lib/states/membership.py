"""Room membership event processing handlers."""

from astrbot.api import logger

from ....constants import TIMESTAMP_BUFFER_MS_1000


class MatrixEventProcessorMembershipMixin:
    """Process membership and system events for room visibility."""

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
