"""
Matrix Sync Manager
Handles the sync loop and event distribution
"""

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..constants import DEFAULT_TIMEOUT_MS_30000, DISPLAY_TRUNCATE_LENGTH_20
from ..plugin_config import get_plugin_config
from ..storage_backend import (
    MatrixFolderDataStore,
    build_folder_namespace,
)


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
        self.storage_backend_config = get_plugin_config().storage_backend_config
        self.data_storage_backend = self.storage_backend_config.backend
        self.pgsql_dsn = self.storage_backend_config.pgsql_dsn
        self.pgsql_schema = self.storage_backend_config.pgsql_schema
        self.pgsql_table_prefix = self.storage_backend_config.pgsql_table_prefix
        self._sync_data_store: MatrixFolderDataStore | None = None

        # 如果提供了新的路径参数，使用新逻辑生成路径
        if homeserver and user_id and store_path:
            from ..storage_paths import MatrixStoragePaths

            user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
                store_path, homeserver, user_id
            )
            self.sync_store_path = str(user_storage_dir / "sync.json")
            self._sync_data_store = self._build_sync_data_store(user_storage_dir)
        else:
            # 回退到旧的路径参数
            self.sync_store_path = sync_store_path

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
        self._next_batch: str | None = None
        self._first_sync = True
        self._running = False

        # Load saved sync token if available
        self._load_sync_token()

    @staticmethod
    def _sync_json_filename(_: str) -> str:
        return "sync.json"

    def _build_sync_data_store(
        self, user_storage_dir: Path
    ) -> MatrixFolderDataStore | None:
        namespace = build_folder_namespace(
            user_storage_dir, Path(self.store_path) if self.store_path else None
        )
        try:
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend=self.data_storage_backend,
                json_filename_resolver=self._sync_json_filename,
                pgsql_dsn=self.pgsql_dsn,
                pgsql_schema=self.pgsql_schema,
                pgsql_table_prefix=self.pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化 sync 存储后端 {self.data_storage_backend} 失败，回退 json: {e}"
            )
            try:
                return MatrixFolderDataStore(
                    folder_path=user_storage_dir,
                    namespace_key=namespace,
                    backend="json",
                    json_filename_resolver=self._sync_json_filename,
                )
            except Exception:
                return None

    def _load_sync_token(self) -> None:
        """Load sync token from disk for resumption"""
        if self._sync_data_store and self.data_storage_backend != "json":
            try:
                data = self._sync_data_store.get("sync_token")
                if isinstance(data, dict):
                    next_batch = data.get("next_batch")
                    if next_batch:
                        self._next_batch = next_batch
                        self._first_sync = False
                        logger.info(
                            f"恢复同步令牌（backend={self.data_storage_backend}）：{self._next_batch[:DISPLAY_TRUNCATE_LENGTH_20]}..."
                        )
                        return
            except Exception as e:
                logger.warning(f"加载同步令牌失败（{self.data_storage_backend}）：{e}")

        if not self.sync_store_path:
            return

        try:
            if Path(self.sync_store_path).exists():
                with open(self.sync_store_path, encoding="utf-8") as f:
                    data = json.load(f)
                    self._next_batch = data.get("next_batch")
                    if self._next_batch:
                        self._first_sync = False
                        logger.info(
                            f"恢复同步令牌：{self._next_batch[:DISPLAY_TRUNCATE_LENGTH_20]}..."
                        )
                        if (
                            self._sync_data_store
                            and self.data_storage_backend != "json"
                        ):
                            try:
                                self._sync_data_store.upsert("sync_token", data)
                            except Exception as migrate_error:
                                logger.debug(
                                    f"迁移 sync token 到 {self.data_storage_backend} 失败：{migrate_error}"
                                )
        except Exception as e:
            logger.warning(f"加载同步令牌失败：{e}")

    def _save_sync_token(self) -> None:
        """Save sync token to disk for future resumption"""
        if not self._next_batch:
            return

        if self._sync_data_store and self.data_storage_backend != "json":
            try:
                self._sync_data_store.upsert(
                    "sync_token", {"next_batch": self._next_batch}
                )
                return
            except Exception as e:
                logger.warning(f"保存同步令牌失败（{self.data_storage_backend}）：{e}")

        if not self.sync_store_path:
            return

        try:
            from ..storage_paths import MatrixStoragePaths

            sync_path = Path(self.sync_store_path)
            MatrixStoragePaths.ensure_directory(sync_path)
            with open(sync_path, "w", encoding="utf-8") as f:
                json.dump({"next_batch": self._next_batch}, f)
        except Exception as e:
            logger.warning(f"保存同步令牌失败：{e}")

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
        Set callback for room invites

        Args:
            callback: Async function(room_id, invite_data) -> None
        """
        self.on_invite = callback

    def set_leave_callback(self, callback: Callable):
        """
        Set callback for room leave events

        Args:
            callback: Async function(room_id, room_data) -> None
        """
        self.on_leave = callback

    def set_ephemeral_callback(self, callback: Callable):
        """
        Set callback for room ephemeral events

        Args:
            callback: Async function(room_id, events) -> None
        """
        self.on_ephemeral_event = callback

    def set_room_account_data_callback(self, callback: Callable):
        """
        Set callback for room account data events

        Args:
            callback: Async function(room_id, events) -> None
        """
        self.on_room_account_data = callback

    def set_account_data_callback(self, callback: Callable):
        """
        Set callback for global account data events

        Args:
            callback: Async function(events) -> None
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
        Set callback for device list updates

        Args:
            callback: Async function(device_lists) -> None
        """
        self.on_device_lists = callback

    def set_device_one_time_keys_count_callback(self, callback: Callable):
        """
        Set callback for one-time keys count updates

        Args:
            callback: Async function(counts) -> None
        """
        self.on_device_one_time_keys_count = callback

    async def sync_forever(self):
        """
        Run the sync loop forever
        Continuously syncs with the Matrix server and processes events
        """
        self._running = True
        logger.info("Starting Matrix sync loop")

        while self._running:
            try:
                # Execute sync
                sync_response = await self.client.sync(
                    since=self._next_batch,
                    timeout=self.sync_timeout,
                    full_state=self._first_sync,
                )

                self._next_batch = sync_response.get("next_batch")
                self._first_sync = False

                # Save sync token for resumption
                self._save_sync_token()

                # Process global account data
                if self.on_account_data:
                    account_data_events = sync_response.get("account_data", {}).get(
                        "events", []
                    )
                    if account_data_events:
                        await self.on_account_data(account_data_events)

                # Process presence updates
                if self.on_presence_event:
                    presence_events = sync_response.get("presence", {}).get(
                        "events", []
                    )
                    if presence_events:
                        await self.on_presence_event(presence_events)

                # Process device list updates
                if self.on_device_lists:
                    device_lists = sync_response.get("device_lists", {})
                    if device_lists:
                        await self.on_device_lists(device_lists)

                # Process one-time keys count updates
                if self.on_device_one_time_keys_count:
                    otk_counts = sync_response.get("device_one_time_keys_count", {})
                    if otk_counts:
                        await self.on_device_one_time_keys_count(otk_counts)

                # Process to-device messages
                to_device_events = sync_response.get("to_device", {}).get("events", [])
                if to_device_events and self.on_to_device_event:
                    await self.on_to_device_event(to_device_events)

                # Process rooms events
                rooms = sync_response.get("rooms", {})

                # Process joined rooms
                for room_id, room_data in rooms.get("join", {}).items():
                    if self.on_room_event:
                        await self.on_room_event(room_id, room_data)
                    if self.on_ephemeral_event:
                        ephemeral_events = room_data.get("ephemeral", {}).get(
                            "events", []
                        )
                        if ephemeral_events:
                            await self.on_ephemeral_event(room_id, ephemeral_events)
                    if self.on_room_account_data:
                        room_account_data = room_data.get("account_data", {}).get(
                            "events", []
                        )
                        if room_account_data:
                            await self.on_room_account_data(room_id, room_account_data)

                # Process invited rooms
                if self.auto_join_rooms:
                    for room_id, invite_data in rooms.get("invite", {}).items():
                        if self.on_invite:
                            await self.on_invite(room_id, invite_data)

                # Process left rooms
                for room_id, room_data in rooms.get("leave", {}).items():
                    if self.on_leave:
                        await self.on_leave(room_id, room_data)

            except MatrixAPIError as e:
                # Handle token expiration
                if (
                    e.status == 401 or "M_UNKNOWN_TOKEN" in str(e)
                ) and self.on_token_invalid:
                    logger.warning(
                        "Token appears to be invalid or expired. Attempting to refresh..."
                    )
                    if await self.on_token_invalid():
                        logger.info("Token refreshed successfully. Retrying sync...")
                        continue
                    else:
                        logger.error("Failed to refresh token. Stopping sync loop.")
                        raise

                logger.error(f"Matrix API error in sync loop: {e}")
                # Wait a bit before retrying
                await asyncio.sleep(5)

            except KeyboardInterrupt:
                logger.info("Sync loop interrupted by user")
                raise
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                # Wait a bit before retrying
                await asyncio.sleep(5)

    def stop(self):
        """Stop the sync loop"""
        self._running = False
        logger.info("Stopping Matrix sync loop")

    def is_running(self) -> bool:
        """Check if sync loop is running"""
        return self._running

    def get_next_batch(self) -> str | None:
        """Get the current sync batch token"""
        return self._next_batch

    def set_next_batch(self, batch: str):
        """Set the sync batch token (for resuming sync)"""
        self._next_batch = batch
        self._first_sync = False
