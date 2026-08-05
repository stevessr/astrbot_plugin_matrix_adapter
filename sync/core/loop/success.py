"""Successful sync response processing."""

import time

from astrbot.api import logger


class MatrixSyncManagerLoopSuccessMixin:
    """Advance the sync token and dispatch a successful response."""

    async def _handle_sync_success(self, sync_response):
        next_batch = sync_response.get("next_batch")
        if next_batch:
            self._set_next_batch(next_batch)

        if self.on_sync:
            try:
                await self.on_sync(sync_response)
            except Exception as e:
                logger.error(f"Sync response callback failed: {e}")

        await self._save_sync_token()

        await self._dispatch_events(sync_response)

        # Mark success only after dispatch completes
        self._last_sync_success_at = time.time()
        self._sync_consecutive_failures = 0
        self._last_sync_error = None
        self._sync_success_count += 1


__all__ = ["MatrixSyncManagerLoopSuccessMixin"]
