"""Sync network error handling."""

import asyncio
import time


class MatrixSyncManagerLoopNetworkMixin:
    """Record and back off from sync network failures."""

    async def _handle_sync_network_error(self, e):
        self._last_sync_failure_at = time.time()
        self._sync_failure_count += 1
        self._last_sync_error = str(e)
        self._sync_consecutive_failures += 1
        if hasattr(self, "_retry_policy") and self._retry_policy is not None:
            await self._retry_policy.sleep(
                self._sync_consecutive_failures,
                f"Sync network error: {e}",
            )
        else:
            await asyncio.sleep(5)


__all__ = ["MatrixSyncManagerLoopNetworkMixin"]
