"""Sync API error handling."""

import asyncio
import time

from astrbot.api import logger

from ....client.http_client import MatrixAPIError


class MatrixSyncManagerLoopFailureMixin:
    """Record and back off from Matrix API sync failures."""

    async def _handle_sync_api_error(self, e: MatrixAPIError):
        self._last_sync_failure_at = time.time()
        self._sync_failure_count += 1
        self._last_sync_error = str(e)
        self._sync_consecutive_failures += 1

        if e.status in (401, 403):
            logger.error(f"Sync authentication failed: {e}")
            token_refreshed = False
            if self.on_token_invalid:
                try:
                    token_refreshed = await self.on_token_invalid()
                except Exception as cb_e:
                    logger.error(f"Token invalid callback failed: {cb_e}")
            if not token_refreshed:
                await asyncio.sleep(10)
        elif e.status == 429:
            retry_after_ms = (e.data or {}).get("retry_after_ms", 5000)
            logger.warning(f"Sync rate limited, retrying after {retry_after_ms}ms")
            await asyncio.sleep(retry_after_ms / 1000.0)
        elif hasattr(self, "_retry_policy") and self._retry_policy is not None:
            await self._retry_policy.sleep(
                self._sync_consecutive_failures,
                f"Sync API error: {e}",
            )
        else:
            await asyncio.sleep(5)


__all__ = ["MatrixSyncManagerLoopFailureMixin"]
