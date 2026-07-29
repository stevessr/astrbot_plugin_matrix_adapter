"""
Matrix Sync Manager
Handles the sync loop and event distribution
"""

import asyncio
import contextlib
import time
from collections.abc import Callable
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..constants import DEFAULT_TIMEOUT_MS_30000
from ..plugin_config import get_plugin_config
from .sync_retry_policy import SyncRetryPolicy
from .sync_token_store import SyncTokenStore


class MatrixSyncManager:
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
        self._reconnect_requested: bool = False

        # Load saved sync token if available
        self._token_store.load()
        if self._token_store.next_batch:
            self._first_sync = False

    # ---- Callback setters ----

    def set_room_event_callback(self, callback: Callable):
        """
        Set callback for room events

        Args:
            callback: Async function(room_id, room_data) -> None
        """
        self.on_room_event = callback

    def set_to_device_event_callback(self, callback: Callable):
        """
        Set callback for to-device events

        Args:
            callback: Async function(events) -> None
        """
        self.on_to_device_event = callback

    def set_invite_callback(self, callback: Callable):
        """
        Set callback for invite events

        Args:
            callback: Async function(room_id, invite_data) -> None
        """
        self.on_invite = callback

    def set_leave_callback(self, callback: Callable):
        """
        Set callback for leave events

        Args:
            callback: Async function(room_id, leave_data) -> None
        """
        self.on_leave = callback

    def set_ephemeral_callback(self, callback: Callable):
        """
        Set callback for ephemeral events

        Args:
            callback: Async function(room_id, ephemeral_data) -> None
        """
        self.on_ephemeral_event = callback

    def set_room_account_data_callback(self, callback: Callable):
        """
        Set callback for room account data events

        Args:
            callback: Async function(room_id, account_data) -> None
        """
        self.on_room_account_data = callback

    def set_account_data_callback(self, callback: Callable):
        """
        Set callback for account data events

        Args:
            callback: Async function(account_data) -> None
        """
        self.on_account_data = callback

    def set_presence_callback(self, callback: Callable):
        """
        Set callback for presence events

        Args:
            callback: Async function(events) -> None
        """
        self.on_presence_event = callback

    def set_device_lists_callback(self, callback: Callable):
        """
        Set callback for device list changes

        Args:
            callback: Async function(changed, left) -> None
        """
        self.on_device_lists = callback

    def set_device_one_time_keys_count_callback(self, callback: Callable):
        """
        Set callback for one-time keys count changes

        Args:
            callback: Async function(counts) -> None
        """
        self.on_device_one_time_keys_count = callback

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
        if hasattr(self, '_next_batch') and self._next_batch is not None:
            return self._next_batch
        if hasattr(self, '_token_store') and self._token_store is not None:
            return self._token_store.next_batch
        return None

    def _set_next_batch(self, batch: str) -> None:
        """Set the sync token on both the store and the legacy attr."""
        self._next_batch = batch
        if hasattr(self, '_token_store') and self._token_store is not None:
            self._token_store.next_batch = batch

    async def _do_sync(self) -> None:
        """Execute one /sync request and dispatch results."""
        try:
            sync_response = await self.client.sync(
                timeout=self.sync_timeout,
                since=self._get_next_batch(),
            )

            self._last_sync_success_at = time.time()
            self._sync_consecutive_failures = 0
            self._last_sync_error = None
            self._sync_success_count += 1

            next_batch = sync_response.get("next_batch")
            if next_batch:
                self._set_next_batch(next_batch)

            if self.on_sync:
                try:
                    await self.on_sync(sync_response)
                except Exception as e:
                    logger.error(f"Sync response callback failed: {e}")

            await self._dispatch_events(sync_response)

            await self._save_sync_token()

        except asyncio.CancelledError:
            raise
        except MatrixAPIError as e:
            self._last_sync_failure_at = time.time()
            self._sync_failure_count += 1
            self._last_sync_error = str(e)
            self._sync_consecutive_failures += 1

            if e.status in (401, 403):
                logger.error(f"Sync authentication failed: {e}")
                if self.on_token_invalid:
                    try:
                        await self.on_token_invalid()
                    except Exception as cb_e:
                        logger.error(f"Token invalid callback failed: {cb_e}")
                await asyncio.sleep(10)
            elif e.status == 429:
                retry_after_ms = (e.data or {}).get("retry_after_ms", 5000)
                logger.warning(f"Sync rate limited, retrying after {retry_after_ms}ms")
                await asyncio.sleep(retry_after_ms / 1000.0)
            elif hasattr(self, '_retry_policy') and self._retry_policy is not None:
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
            if hasattr(self, '_retry_policy') and self._retry_policy is not None:
                await self._retry_policy.sleep(
                    self._sync_consecutive_failures,
                    f"Sync network error: {e}",
                )
            else:
                await asyncio.sleep(5)

    async def _dispatch_events(self, sync_response: dict) -> None:
        """Dispatch sync response fields to registered callbacks."""
        tasks: list[asyncio.Task] = []

        # 1. To-device events — processed first (may contain room keys needed
        #    to decrypt room events in the same sync response).
        to_device = sync_response.get("to_device", {})
        events = to_device.get("events", [])
        if events and self.on_to_device_event:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_to_device_event", self.on_to_device_event, events
                )
            )
            tasks.append(task)

        # 2. Device list changes — pass full dict (original callback interface)
        device_lists = sync_response.get("device_lists", {})
        if device_lists and self.on_device_lists:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_device_lists", self.on_device_lists, device_lists
                )
            )
            tasks.append(task)

        # 3. One-time keys count + unused fallback key types
        device_one_time_keys_count = sync_response.get("device_one_time_keys_count", {})
        unused_fallback_key_types = sync_response.get(
            "device_unused_fallback_key_types"
        )
        if device_one_time_keys_count and self.on_device_one_time_keys_count:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_device_one_time_keys_count",
                    self.on_device_one_time_keys_count,
                    device_one_time_keys_count,
                    unused_fallback_key_types,
                )
            )
            tasks.append(task)

        # 4. Presence
        presence = sync_response.get("presence", {})
        presence_events = presence.get("events", [])
        if presence_events and self.on_presence_event:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_presence_event", self.on_presence_event, presence_events
                )
            )
            tasks.append(task)

        # 5. Account data
        account_data = sync_response.get("account_data", {})
        account_data_events = account_data.get("events", [])
        if account_data_events and self.on_account_data:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_account_data", self.on_account_data, account_data_events
                )
            )
            tasks.append(task)

        # 6. Room events — process in parallel
        rooms = sync_response.get("rooms", {})
        room_tasks = []

        # Join events
        join_rooms = rooms.get("join", {})
        for room_id, room_data in join_rooms.items():
            if self.on_room_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_event:{room_id}",
                            self.on_room_event,
                            room_id,
                            room_data,
                        )
                    )
                )
            # Ephemeral events per room
            ephemeral = room_data.get("ephemeral", {})
            ephemeral_events = ephemeral.get("events", [])
            if ephemeral_events and self.on_ephemeral_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_ephemeral_event:{room_id}",
                            self.on_ephemeral_event,
                            room_id,
                            ephemeral_events,
                        )
                    )
                )
            # Room account data
            room_account_data = room_data.get("account_data", {})
            room_account_data_events = room_account_data.get("events", [])
            if room_account_data_events and self.on_room_account_data:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_account_data:{room_id}",
                            self.on_room_account_data,
                            room_id,
                            room_account_data_events,
                        )
                    )
                )

        # Invite events
        invite_rooms = rooms.get("invite", {})
        for room_id, invite_data in invite_rooms.items():
            if self.on_invite:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_invite:{room_id}",
                            self.on_invite,
                            room_id,
                            invite_data,
                        )
                    )
                )

        # Leave events
        leave_rooms = rooms.get("leave", {})
        for room_id, leave_data in leave_rooms.items():
            if self.on_leave:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_leave:{room_id}",
                            self.on_leave,
                            room_id,
                            leave_data,
                        )
                    )
                )

        tasks.extend(room_tasks)

        # Track and await all callbacks
        self._active_callback_tasks.update(tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._active_callback_tasks.difference_update(tasks)

    async def _run_callback_with_guard(
        self,
        callback_name: str,
        callback: Callable,
        *args,
    ) -> None:
        """Run a single callback with timeout protection."""
        timeout = (
            self._retry_policy.callback_timeout
            if hasattr(self, '_retry_policy') and self._retry_policy is not None
            else 30
        )
        try:
            if timeout > 0:
                await asyncio.wait_for(callback(*args), timeout=timeout)
            else:
                await callback(*args)
        except asyncio.TimeoutError:
            logger.warning(
                f"Sync callback timed out: {callback_name} ({timeout:.1f}s)"
            )
        except Exception as e:
            logger.error(f"Sync callback failed: {callback_name} ({e})")

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
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(
                    self._sync_request_task, timeout=timeout_seconds
                )

    def is_running(self) -> bool:
        """Check if sync loop is running."""
        return self._running

    # ---- Sync token management ----

    # Backward-compatible wrappers for tests that access _save_sync_token / _next_batch directly
    _save_sync_token = None  # set by tests via __new__; real usage goes through _token_store

    async def _save_sync_token(self, *, force: bool = False) -> None:
        """Legacy wrapper — delegates to _token_store.save() when available."""
        if hasattr(self, '_token_store') and self._token_store is not None:
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
        self._reconnect_requested = True
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
            "next_batch_truncated": (
                f"{next_batch[:20]}..." if next_batch else None
            ),
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
