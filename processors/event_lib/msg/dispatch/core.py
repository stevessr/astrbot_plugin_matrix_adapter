"""Message event processing orchestration."""

from astrbot.api import logger

from .....constants import TIMESTAMP_BUFFER_MS_1000


class MatrixEventProcessorMessagesCoreMixin:
    """Mixin for message event processing."""

    async def _process_message_event(self, room, event):
        """
        Process a message event

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"room timeline 事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

            # Check if message is encrypted
            event_type = event.event_type
            event_content = event.content

            # Handle encrypted messages first (decrypt + verification routing)
            decrypted = await self._handle_encrypted_message_event(
                room, event, sender, event_type, event_content
            )
            if decrypted is None:
                return
            event, event_type, event_content = decrypted

            # Ignore messages from self (unless it was a verification request handled above)
            if sender == self.user_id:
                # Double check to ensure we don't process own messages
                logger.debug(f"忽略来自自身的消息：{event.event_id}")
                return

            # Filter historical messages: ignore events before startup
            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):  # Allow 1s drift
                logger.debug(
                    f"忽略启动前的历史消息："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            # Message deduplication: check if already processed
            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复消息：{event.event_id}")
                return

            # MSC4145 / MSC2676: validate and normalize m.replace edits.
            if await self._normalize_message_edit(event, event_content):
                return

            # Call message callback + send read receipt
            await self._deliver_message(room, event, event_content)

        except Exception as e:
            logger.error(f"处理消息事件时出错：{e}")
