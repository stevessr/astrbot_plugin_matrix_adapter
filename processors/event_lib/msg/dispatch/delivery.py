"""Message callback delivery and read-receipt sending."""

from astrbot.api import logger


class MatrixEventProcessorMessagesDeliveryMixin:
    """Deliver processed messages to the callback and send read receipts."""

    async def _deliver_message(self, room, event, event_content) -> None:
        # Call message callback
        if self.on_message:
            await self._persist_interacted_user(room, event)
            await self.on_message(room, event)
            self._mark_message_processed(event.event_id)

            # Send read receipt after successful processing.
            # When the message is in a thread, pass the thread ID so the
            # read receipt marks the thread as read (MSC3771).
            from .....config.plugin import get_plugin_config as _get_plugin_config

            if _get_plugin_config().send_read_receipt:
                try:
                    thread_id = None
                    relates_to = event_content.get("m.relates_to", {})
                    if (
                        isinstance(relates_to, dict)
                        and relates_to.get("rel_type") == "m.thread"
                    ):
                        thread_id = relates_to.get("event_id")
                    await self.client.send_read_receipt(
                        room.room_id, event.event_id, thread_id=thread_id
                    )
                    logger.debug(
                        f"已发送事件 {event.event_id} 的已读回执"
                        + (f" (thread={thread_id})" if thread_id else "")
                    )
                except Exception as e:
                    logger.debug(f"发送已读回执失败：{e}")
