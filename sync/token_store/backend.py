"""Backend persistence for sync tokens."""

import asyncio
from pathlib import Path

from astrbot.api import logger

from ...storage.backend import MatrixFolderDataStore, build_folder_namespace


class SyncTokenBackendMixin:
    @staticmethod
    def _sync_json_filename(_: str) -> str:
        return "sync.json"

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

    def _load_sync_token_from_backend(self) -> str | None:
        if not self._sync_data_store:
            return None
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
        return None

    def _migrate_to_backend(self, data: dict) -> None:
        if self._sync_data_store:
            try:
                self._sync_data_store.upsert("sync_token", data)
            except Exception as e:
                logger.debug(f"迁移 sync token 失败：{e}")

    async def _save_sync_token_to_backend(self, payload: dict, now: float) -> bool:
        if not self._sync_data_store:
            return False
        try:
            await asyncio.to_thread(self._sync_data_store.upsert, "sync_token", payload)
            self._last_saved_next_batch = self._next_batch
            self._last_save_at = now
            return True
        except Exception as e:
            logger.warning(f"保存同步令牌失败：{e}")
            return False


__all__ = ["SyncTokenBackendMixin"]
