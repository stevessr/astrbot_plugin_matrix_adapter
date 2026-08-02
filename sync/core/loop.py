"""Matrix sync loop and request execution."""

import asyncio
import time

from astrbot.api import logger

from ...client.http_client import MatrixAPIError


class MatrixSyncManagerLoopMixin:
    """Run Matrix sync requests and process their responses."""

    async def sync_forever(self):
        """
        Main sync loop - runs forever until stop is called
        """
        self._running = True
        logger.info("Matrix sync loop started")

        while self._running:
            try:
                # Wrap the sync request in a cancellable task so
                # request_reconnect() can interrupt an in-flight /sync.
                self._sync_request_task = asyncio.create_task(self._do_sync())
                try:
                    await self._sync_request_task
                except asyncio.CancelledError:
                    # Intentionally cancelled by request_reconnect — retry
                    pass
            except Exception as e:
                logger.error(f"Sync loop unexpected error: {e}")
                if self._running:
                    await asyncio.sleep(5)
            finally:
                self._sync_request_task = None
        self._running = False
        logger.info("Matrix sync loop stopped")

    async def _do_sync(self) -> None:
        """Execute one /sync request and dispatch results."""
        try:
            sync_kwargs = {
                "timeout": self.sync_timeout,
                "since": self._get_next_batch(),
            }
            filter_id = getattr(self, "_filter_id", None)
            if filter_id is not None:
                sync_kwargs["filter_id"] = filter_id
            sync_response = await self.client.sync(**sync_kwargs)

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

        except asyncio.CancelledError:
            raise
        except MatrixAPIError as e:
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
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
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
