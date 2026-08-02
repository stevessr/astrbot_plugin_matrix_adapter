"""Matrix sync manager construction and state initialization."""

import asyncio
from collections.abc import Callable
from pathlib import Path

from ...config.plugin import get_plugin_config
from ...constants import DEFAULT_TIMEOUT_MS_30000
from ..sync_retry_policy import SyncRetryPolicy
from ..token_store import SyncTokenStore


class MatrixSyncManagerStateMixin:
    """Initialize sync manager dependencies, callbacks, and runtime state."""

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
