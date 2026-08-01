"""
Matrix Sync Manager
Handles the sync loop and event distribution
"""

import asyncio
import time
from collections.abc import Callable
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..constants import DEFAULT_TIMEOUT_MS_30000
from ..plugin_config import get_plugin_config
from .sync_lib import (
    MatrixSyncManagerCallbacksMixin,
    MatrixSyncManagerDispatchMixin,
)
from .sync_retry_policy import SyncRetryPolicy
from .sync_token_store import SyncTokenStore


class MatrixSyncManager(
    MatrixSyncManagerCallbacksMixin,
    MatrixSyncManagerDispatchMixin,
):
    """
    Manages the Matrix sync loop and event processing
    """

    def __init__(
        self,
        client,
        sync_timeout: int = DEFAULT_TIMEOUT_MS_30000,
        auto_join_rooms: bool = True,
        sync_store_path: str | None = None,
        homeserver: str | None = None,
        user_id: str | None = None,
        store_path: str | Path | None = None,
        on_token_invalid: Callable | None = None,
        filter_id: str | None = None,
    ):
        """
        Initialize sync manager

        Args:
            client: Matrix HTTP client
            sync_timeout: Sync timeout in milliseconds
            auto_join_rooms: Whether to auto-join invited rooms
            sync_store_path: Path to store sync token for resumption (deprecated)
            homeserver: Matrix homeserver URL
            user_id: Matrix user ID
            store_path: Base storage path
            on_token_invalid: Callback to handle invalid token (e.g., refresh token)
        """
        self.client = client
        self.sync_timeout = sync_timeout
        self.auto_join_rooms = auto_join_rooms
        self.homeserver = homeserver
        self.user_id = user_id
        self.store_path = store_path
        self.on_token_invalid = on_token_invalid
        self._filter_id = filter_id
        storage_config = get_plugin_config().storage_backend_config

        # Delegated components
        self._token_store = SyncTokenStore(
            homeserver=homeserver,
            user_id=user_id,
            store_path=store_path,
            sync_store_path=sync_store_path,
            storage_backend_config=storage_config,
        )
        self._retry_policy = SyncRetryPolicy()

        # Event callbacks
        self.on_room_event: Callable | None = None
        self.on_to_device_event: Callable | None = None
        self.on_invite: Callable | None = None
        self.on_knock: Callable | None = None
        self.on_leave: Callable | None = None
        self.on_ephemeral_event: Callable | None = None
        self.on_room_account_data: Callable | None = None
        self.on_account_data: Callable | None = None
        self.on_presence_event: Callable | None = None
        self.on_device_lists: Callable | None = None
        self.on_device_one_time_keys_count: Callable | None = None
        self.on_sync: Callable | None = None

        # Sync state
        self._first_sync = True
        self._running = False
        self._sync_consecutive_failures: int = 0
        self._sync_request_task: asyncio.Task | None = None
        self._active_callback_tasks: set[asyncio.Task] = set()
        self._last_sync_success_at: float | None = None
        self._last_sync_failure_at: float | None = None
        self._last_sync_error: str | None = None
        self._sync_success_count: int = 0
        self._sync_failure_count: int = 0
        # Load saved sync token if available
        self._token_store.load()
        if self._token_store.next_batch:
            self._first_sync = False

    # ---- Callback setters ----

    # ---- Sync loop ----

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

    def _get_next_batch(self) -> str | None:
        """Get the current sync token from the token store (or legacy attr)."""
        if hasattr(self, "_next_batch") and self._next_batch is not None:
            return self._next_batch
        if hasattr(self, "_token_store") and self._token_store is not None:
            return self._token_store.next_batch
        return None

    def _set_next_batch(self, batch: str) -> None:
        """Set the sync token on both the store and the legacy attr."""
        self._next_batch = batch
        if hasattr(self, "_token_store") and self._token_store is not None:
            self._token_store.next_batch = batch

    async def _do_sync(self) -> None:
        """Execute one /sync request and dispatch results."""
        try:
            sync_response = await self.client.sync(
                timeout=self.sync_timeout,
                since=self._get_next_batch(),
                filter_id=getattr(self, "_filter_id", None),
            )

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

    # ---- Lifecycle ----

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

    # ---- Sync token management ----

    async def _save_sync_token(self, *, force: bool = False) -> None:
        """Persist current sync token to storage."""
        if hasattr(self, "_token_store") and self._token_store is not None:
            await self._token_store.save(force=force)

    def get_next_batch(self) -> str | None:
        """Get the current sync token."""
        return self._get_next_batch()

    def set_next_batch(self, batch: str):
        """Override the sync token (for resumption)."""
        self._set_next_batch(batch)
        self._first_sync = False

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
