"""Sync manager lifecycle and status operations."""

import asyncio

from astrbot.api import logger


class MatrixSyncManagerLifecycleMixin:
    """Stop, reconnect, and inspect the Matrix sync manager."""

    def stop(self):
        """Signal the sync loop to stop (non-blocking)."""
        self._running = False
        logger.debug("Sync loop stop requested")

    async def stop_and_wait(self, timeout_seconds: float = 5.0) -> None:
        """Signal stop and wait for the sync task to finish."""
        self.stop()
        if self._sync_request_task and not self._sync_request_task.done():
            self._sync_request_task.cancel()
            try:
                await asyncio.wait_for(self._sync_request_task, timeout=timeout_seconds)
            except asyncio.TimeoutError:
                logger.warning("等待 sync 任务停止超时")

    def is_running(self) -> bool:
        """Check if sync loop is running."""
        return self._running

    def request_reconnect(self) -> bool:
        """Request reconnection by interrupting current sync."""
        if not self._running:
            return False
        self._sync_consecutive_failures = 0
        self._last_sync_error = None
        sync_task = self._sync_request_task
        if sync_task and not sync_task.done():
            sync_task.cancel()
        return True

    def status_snapshot(self) -> dict:
        """Return current status snapshot for monitoring/debugging."""
        next_batch = self._get_next_batch()
        return {
            "running": self._running,
            "first_sync": self._first_sync,
            "next_batch_truncated": (f"{next_batch[:20]}..." if next_batch else None),
            "consecutive_failures": self._sync_consecutive_failures,
            "last_success_at": self._last_sync_success_at,
            "last_failure_at": self._last_sync_failure_at,
            "last_error": self._last_sync_error,
            "last_error_truncated": (
                self._last_sync_error[:200] if self._last_sync_error else None
            ),
            "sync_success_count": self._sync_success_count,
            "failure_count": self._sync_failure_count,
            "active_callback_tasks": len(self._active_callback_tasks),
        }
