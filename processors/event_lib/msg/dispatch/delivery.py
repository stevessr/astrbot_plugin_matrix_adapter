"""Message callback delivery and read-receipt sending."""

import asyncio

from astrbot.api import logger


class MatrixEventProcessorMessagesDeliveryMixin:
    """Deliver processed messages to the callback and send read receipts."""

    @staticmethod
    def _read_receipt_thread_id(event_content: dict) -> str | None:
        relates_to = event_content.get("m.relates_to", {})
        if (
            isinstance(relates_to, dict)
            and relates_to.get("rel_type") == "m.thread"
        ):
            thread_id = relates_to.get("event_id")
            return str(thread_id) if thread_id else None
        return None

    async def _send_configured_read_receipt(
        self,
        room_id: str,
        event_id: str,
        receipt_type: str,
        thread_id: str | None,
    ) -> None:
        if receipt_type == "private":
            await self.client.send_read_receipt_private(
                room_id, event_id, thread_id=thread_id
            )
            wire_type = "m.read.private"
        else:
            await self.client.send_read_receipt(
                room_id, event_id, thread_id=thread_id
            )
            wire_type = "m.read"

        logger.debug(
            f"已发送事件 {event_id} 的已读回执 ({wire_type})"
            + (f" (thread={thread_id})" if thread_id else "")
        )

    def _queue_batched_read_receipt(
        self,
        room_id: str,
        event_id: str,
        thread_id: str | None,
        interval_ms: int,
    ) -> None:
        """Queue the newest receipt per room in one lazy, fixed batch window."""
        pending = getattr(self, "_read_receipt_batch_pending", None)
        if pending is None:
            pending = {}
            self._read_receipt_batch_pending = pending

        # Matrix receipts are monotonic per room. Within one fixed window only
        # the newest successfully processed event needs to be acknowledged.
        pending[room_id] = (event_id, thread_id)

        task = getattr(self, "_read_receipt_batch_task", None)
        if task is None or task.done():
            # Lazy window: no periodic background loop. The first queued
            # message opens one fixed window; later messages do not reset it.
            self._read_receipt_batch_task = asyncio.create_task(
                self._flush_batched_read_receipts(interval_ms)
            )

    async def _flush_batched_read_receipts(self, interval_ms: int) -> None:
        try:
            await asyncio.sleep(max(0.1, interval_ms / 1000))

            # Snapshot and close this window before the first network await.
            # A message arriving while the snapshot is being sent starts a new
            # independent window rather than becoming stranded in this task.
            pending = getattr(self, "_read_receipt_batch_pending", {})
            self._read_receipt_batch_pending = {}
            self._read_receipt_batch_task = None

            for room_id, (event_id, thread_id) in pending.items():
                try:
                    await self._send_configured_read_receipt(
                        room_id,
                        event_id,
                        "public",
                        thread_id,
                    )
                except Exception as e:
                    logger.debug(
                        f"批次发送房间 {room_id} 的已读回执失败：{e}"
                    )
        except asyncio.CancelledError:
            raise
        finally:
            current = getattr(self, "_read_receipt_batch_task", None)
            if current is asyncio.current_task():
                self._read_receipt_batch_task = None

    async def _deliver_message(self, room, event, event_content) -> None:
        # Call message callback
        if self.on_message:
            await self._persist_interacted_user(room, event)
            await self.on_message(room, event)
            self._mark_message_processed(event.event_id)

            # Send a receipt only after successful processing. Batch mode uses
            # a lazy fixed window and sends one public m.read per room for the
            # newest event observed during that window.
            from .....config.plugin import get_plugin_config as _get_plugin_config

            config = _get_plugin_config()
            receipt_type = getattr(config, "read_receipt_type", None)
            if receipt_type is None:
                receipt_type = "public" if config.send_read_receipt else "none"
            if receipt_type == "none":
                return

            thread_id = self._read_receipt_thread_id(event_content)
            if receipt_type == "batch":
                self._queue_batched_read_receipt(
                    room.room_id,
                    event.event_id,
                    thread_id,
                    getattr(config, "read_receipt_batch_interval_ms", 2000),
                )
                return

            try:
                await self._send_configured_read_receipt(
                    room.room_id,
                    event.event_id,
                    receipt_type,
                    thread_id,
                )
            except Exception as e:
                logger.debug(f"发送已读回执失败：{e}")
