"""Matrix Event Processor - /sync leave stream handler."""

from astrbot.api import logger


class MatrixEventProcessorStreamsLeaveMixin:
    """Process room leave events from /sync."""

    async def process_leave_events(self, room_id: str, room_data: dict):
        """Process room leave events from /sync."""
        self.room_account_data.pop(room_id, None)
        self.typing.pop(room_id, None)
        self.receipts.pop(room_id, None)
        logger.info(f"已离开房间 {room_id}，清理相关缓存")


__all__ = ["MatrixEventProcessorStreamsLeaveMixin"]
