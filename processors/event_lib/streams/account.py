"""Matrix Event Processor - /sync account data stream handlers."""

from astrbot.api import logger


class MatrixEventProcessorStreamsAccountMixin:
    """Process global and room account data events from /sync."""

    async def process_account_data_events(self, events: list):
        """Process global account data events from /sync."""
        for event in events:
            event_type = event.get("type")
            content = event.get("content", {})
            if not event_type:
                continue
            self.global_account_data[event_type] = content
            logger.debug(f"更新全局 account_data: {event_type}")

    async def process_room_account_data_events(self, room_id: str, events: list):
        """Process room account data events from /sync."""
        room_data = self.room_account_data.setdefault(room_id, {})
        for event in events:
            event_type = event.get("type")
            content = event.get("content", {})
            if not event_type:
                continue
            room_data[event_type] = content
            logger.debug(f"更新房间 {room_id} account_data: {event_type}")


__all__ = ["MatrixEventProcessorStreamsAccountMixin"]
