"""
Sync Token Store — persistent sync-token (next_batch) management.

Extracted from MatrixSyncManager to separate persistence from loop orchestration.
"""

import asyncio
import json
from pathlib import Path

from astrbot.api import logger

from ..storage.backend import MatrixFolderDataStore, build_folder_namespace
from ..storage.paths import MatrixStoragePaths


class SyncTokenStore:
    """Persist and load the Matrix /sync next_batch token."""

    _SAVE_INTERVAL_SECONDS = 5.0

    @staticmethod
    def _sync_json_filename(_: str) -> str:
        return "sync.json"

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
        self._sync_data_store: MatrixFolderDataStore | None = None
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

    def _build_sync_data_store(
        self, user_storage_dir: Path, storage_config
    ) -> MatrixFolderDataStore | None:
        if storage_config is None:
            return None
        namespace = build_folder_namespace(
            user_storage_dir,
            Path(self.sync_store_path).parent if self.sync_store_path else None,
        )
        try:
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend=storage_config.backend,
                json_filename_resolver=self._sync_json_filename,
                pgsql_dsn=storage_config.pgsql_dsn,
                pgsql_schema=storage_config.pgsql_schema,
                pgsql_table_prefix=storage_config.pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化 sync 存储后端 {storage_config.backend} 失败，回退 json: {e}"
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
        if self._sync_data_store:
            try:
                data = self._sync_data_store.get("sync_token")
                if isinstance(data, dict):
                    token = data.get("next_batch")
                    if token:
                        self._next_batch = token
                        logger.info(
                            f"恢复同步令牌（backend={self._sync_data_store.backend}）"
                        )
                        return token
            except Exception as e:
                logger.warning(f"加载同步令牌失败：{e}")

        if not self.sync_store_path:
            return None

        try:
            path = Path(self.sync_store_path)
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    self._next_batch = data.get("next_batch")
                    if self._next_batch:
                        logger.info("恢复同步令牌（JSON 回退）")
                        self._migrate_to_backend(data)
                    return self._next_batch
        except Exception as e:
            logger.warning(f"加载同步令牌失败（JSON 回退）：{e}")

        return None

    def _migrate_to_backend(self, data: dict) -> None:
        if self._sync_data_store:
            try:
                self._sync_data_store.upsert("sync_token", data)
            except Exception as e:
                logger.debug(f"迁移 sync token 失败：{e}")

    @staticmethod
    def _write_sync_token_file(sync_path: Path, payload: dict) -> None:
        with open(sync_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    async def save(self, *, force: bool = False) -> None:
        """Persist the current token (throttled to _SAVE_INTERVAL_SECONDS)."""
        if not self._next_batch:
            return

        loop = asyncio.get_running_loop()
        now = loop.time()
        if not force and (now - self._last_save_at) < self._SAVE_INTERVAL_SECONDS:
            return

        payload = {"next_batch": self._next_batch}

        if self._sync_data_store:
            try:
                await asyncio.to_thread(
                    self._sync_data_store.upsert, "sync_token", payload
                )
                self._last_saved_next_batch = self._next_batch
                self._last_save_at = now
                return
            except Exception as e:
                logger.warning(f"保存同步令牌失败：{e}")

        if not self.sync_store_path:
            return

        try:
            sync_path = Path(self.sync_store_path)
            await asyncio.to_thread(
                MatrixStoragePaths.ensure_directory,
                sync_path,
                treat_as_file=True,
            )
            await asyncio.to_thread(self._write_sync_token_file, sync_path, payload)
            self._last_saved_next_batch = self._next_batch
            self._last_save_at = now
        except Exception as e:
            logger.warning(f"保存同步令牌失败：{e}")
