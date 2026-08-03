"""Guarded callback execution for the sync manager."""

import asyncio
from collections.abc import Callable

from astrbot.api import logger


class MatrixSyncManagerCallbackGuardMixin:
    """Run sync callbacks with timeout and error protection."""

    async def _run_callback_with_guard(
        self,
        callback_name: str,
        callback: Callable,
        *args,
    ) -> None:
        """Run a single callback with timeout protection."""
        timeout = (
            self._retry_policy.callback_timeout
            if hasattr(self, "_retry_policy") and self._retry_policy is not None
            else 30
        )
        try:
            if timeout > 0:
                await asyncio.wait_for(callback(*args), timeout=timeout)
            else:
                await callback(*args)
        except asyncio.TimeoutError:
            logger.warning(f"Sync callback timed out: {callback_name} ({timeout:.1f}s)")
        except Exception as e:
            logger.error(f"Sync callback failed: {callback_name} ({e})")
