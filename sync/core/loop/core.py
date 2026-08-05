"""Matrix sync loop and request execution."""

import asyncio

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from .failure import MatrixSyncManagerLoopFailureMixin
from .network import MatrixSyncManagerLoopNetworkMixin
from .request import MatrixSyncManagerLoopRequestMixin
from .success import MatrixSyncManagerLoopSuccessMixin


class MatrixSyncManagerLoopOrchestratorMixin(
    MatrixSyncManagerLoopRequestMixin,
    MatrixSyncManagerLoopSuccessMixin,
    MatrixSyncManagerLoopFailureMixin,
    MatrixSyncManagerLoopNetworkMixin,
):
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
            sync_response = await self._execute_sync_request()
            await self._handle_sync_success(sync_response)
        except asyncio.CancelledError:
            raise
        except MatrixAPIError as e:
            await self._handle_sync_api_error(e)
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            await self._handle_sync_network_error(e)


__all__ = [
    "MatrixSyncManagerLoopFailureMixin",
    "MatrixSyncManagerLoopNetworkMixin",
    "MatrixSyncManagerLoopOrchestratorMixin",
    "MatrixSyncManagerLoopRequestMixin",
    "MatrixSyncManagerLoopSuccessMixin",
]
