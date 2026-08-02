"""Sync token state and persistence orchestration."""

import asyncio
from pathlib import Path

from ...storage.paths import MatrixStoragePaths
from .backend import SyncTokenBackendMixin
from .fallback import SyncTokenFallbackMixin


class SyncTokenStore(SyncTokenBackendMixin, SyncTokenFallbackMixin):
    """Persist and load the Matrix /sync next_batch token."""

    _SAVE_INTERVAL_SECONDS = 5.0

    def __init__(
        self,
        *,
        homeserver: str | None = None,
        user_id: str | None = None,
        store_path: str | Path | None = None,
        sync_store_path: str | None = None,
        storage_backend_config=None,
    ):
        self._next_batch: str | None = None
        self._last_saved_next_batch: str | None = None
        self._last_save_at: float = 0.0
        self._sync_data_store = None
        self.sync_store_path = sync_store_path

        if homeserver and user_id and store_path:
            user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
                store_path, homeserver, user_id
            )
            self.sync_store_path = str(user_storage_dir / "sync.json")
            self._sync_data_store = self._build_sync_data_store(
                user_storage_dir,
                storage_backend_config,
            )

    @property
    def next_batch(self) -> str | None:
        return self._next_batch

    @next_batch.setter
    def next_batch(self, value: str | None) -> None:
        self._next_batch = value

    @property
    def first_sync(self) -> bool:
        return self._next_batch is None

    def load(self) -> str | None:
        """Load sync token from persistent storage.

        Returns the loaded token, or None if none was saved.
        """
        token = self._load_sync_token_from_backend()
        if token:
            return token
        return self._load_sync_token_from_file()

    async def save(self, *, force: bool = False) -> None:
        """Persist the current token (throttled to _SAVE_INTERVAL_SECONDS)."""
        if not self._next_batch:
            return

        loop = asyncio.get_running_loop()
        now = loop.time()
        if not force and (now - self._last_save_at) < self._SAVE_INTERVAL_SECONDS:
            return

        payload = {"next_batch": self._next_batch}
        if await self._save_sync_token_to_backend(payload, now):
            return
        await self._save_sync_token_to_file(payload, now)


__all__ = ["SyncTokenStore"]
