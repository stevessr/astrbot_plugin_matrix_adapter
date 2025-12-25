"""
Matrix Sync Manager
Handles the sync loop and event distribution
"""

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

from astrbot.api import logger

from ..constants import DEFAULT_TIMEOUT_MS_30000, DISPLAY_TRUNCATE_LENGTH_20


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
        store_path: str | None = None,
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
        """
        self.client = client
        self.sync_timeout = sync_timeout
        self.auto_join_rooms = auto_join_rooms
        self.homeserver = homeserver
        self.user_id = user_id
        self.store_path = store_path

        # 如果提供了新的路径参数，使用新逻辑生成路径
        if homeserver and user_id and store_path:
            from ..storage_paths import MatrixStoragePaths
            self.sync_store_path = str(MatrixStoragePaths.get_sync_file_path(
                store_path, homeserver, user_id
            ))
        else:
            # 回退到旧的路径参数
            self.sync_store_path = sync_store_path

        # Event callbacks
        self.on_room_event: Callable | None = None
        self.on_to_device_event: Callable | None = None
        self.on_invite: Callable | None = None
        self.on_sync: Callable | None = None

        # Sync state
        self._next_batch: str | None = None
        self._first_sync = True
        self._running = False

        # Load saved sync token if available
        self._load_sync_token()

    def _load_sync_token(self) -> None:
        """Load sync token from disk for resumption"""
        if not self.sync_store_path:
            return

        try:
            if Path(self.sync_store_path).exists():
                with open(self.sync_store_path) as f:
                    data = json.load(f)
                    self._next_batch = data.get("next_batch")
                    if self._next_batch:
                        self._first_sync = False
                        logger.info(
                            f"恢复同步令牌：{self._next_batch[:DISPLAY_TRUNCATE_LENGTH_20]}..."
                        )
        except Exception as e:
            logger.warning(f"加载同步令牌失败：{e}")

    def _save_sync_token(self) -> None:
        """Save sync token to disk for future resumption"""
        if not self.sync_store_path or not self._next_batch:
            return

        try:
            from ..storage_paths import MatrixStoragePaths
            sync_path = Path(self.sync_store_path)
            MatrixStoragePaths.ensure_directory(sync_path)
            with open(sync_path, "w") as f:
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

                # Process invited rooms
                if self.auto_join_rooms:
                    for room_id, invite_data in rooms.get("invite", {}).items():
                        if self.on_invite:
                            await self.on_invite(room_id, invite_data)

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
