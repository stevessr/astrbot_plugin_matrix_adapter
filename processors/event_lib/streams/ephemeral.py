"""Matrix Event Processor - /sync presence and ephemeral stream handlers."""

from astrbot.api import logger


class MatrixEventProcessorStreamsEphemeralMixin:
    """Process presence and ephemeral events from /sync."""

    async def process_presence_events(self, events: list):
        """Process presence events from /sync."""
        for event in events:
            user_id = event.get("sender") or event.get("user_id")
            if not user_id:
                continue
            self.presence[user_id] = event
        if events:
            logger.debug(f"更新 {len(events)} 条 presence 事件")

    async def process_ephemeral_events(self, room_id: str, events: list):
        """Process ephemeral events (typing, receipts) from /sync."""
        for event in events:
            event_type = event.get("type")
            content = event.get("content", {})
            match event_type:
                case "m.typing":
                    user_ids = content.get("user_ids", [])
                    if isinstance(user_ids, list):
                        self.typing[room_id] = set(user_ids)
                        logger.debug(
                            f"房间 {room_id} typing: {len(self.typing[room_id])} users"
                        )
                case "m.receipt":
                    room_receipts = self.receipts.setdefault(room_id, {})
                    for event_id, receipt_types in content.items():
                        room_receipts[event_id] = receipt_types
                    logger.debug(f"房间 {room_id} receipt 更新 {len(content)} 条事件")
                case _:
                    logger.debug(f"未处理的 ephemeral 事件：{event_type}")


__all__ = ["MatrixEventProcessorStreamsEphemeralMixin"]
