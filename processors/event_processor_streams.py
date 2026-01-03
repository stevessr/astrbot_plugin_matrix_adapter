"""
Matrix Event Processor - /sync stream handlers.
"""

from astrbot.api import logger


class MatrixEventProcessorStreams:
    """Mixin for /sync stream processing."""

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
            if event_type == "m.typing":
                user_ids = content.get("user_ids", [])
                if isinstance(user_ids, list):
                    self.typing[room_id] = set(user_ids)
                    logger.debug(
                        f"房间 {room_id} typing: {len(self.typing[room_id])} users"
                    )
            elif event_type == "m.receipt":
                room_receipts = self.receipts.setdefault(room_id, {})
                for event_id, receipt_types in content.items():
                    room_receipts[event_id] = receipt_types
                logger.debug(f"房间 {room_id} receipt 更新 {len(content)} 条事件")
            else:
                logger.debug(f"未处理的 ephemeral 事件：{event_type}")

    async def process_device_lists(self, device_lists: dict):
        """Process device list updates from /sync."""
        changed = device_lists.get("changed", []) or []
        left = device_lists.get("left", []) or []
        if isinstance(changed, list):
            self.device_lists["changed"].update(changed)
        if isinstance(left, list):
            self.device_lists["left"].update(left)
        logger.debug(f"设备列表更新：changed={len(changed)} left={len(left)}")

    async def process_device_one_time_keys_count(self, counts: dict):
        """Process one-time keys count updates from /sync."""
        if isinstance(counts, dict):
            self.one_time_keys_count = counts
            logger.debug(f"更新 device_one_time_keys_count: {list(counts.keys())}")

    async def process_leave_events(self, room_id: str, room_data: dict):
        """Process room leave events from /sync."""
        self.room_account_data.pop(room_id, None)
        self.typing.pop(room_id, None)
        self.receipts.pop(room_id, None)
        logger.info(f"已离开房间 {room_id}，清理相关缓存")
