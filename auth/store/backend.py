"""Authentication token storage backend integration."""

import threading
from pathlib import Path

from ...config.plugin import get_plugin_config
from ...storage.backend import (
    MatrixFolderDataStore,
    StorageBackendConfig,
    build_folder_namespace,
)


class MatrixAuthStoreBackendMixin:
    """Build and write authentication data stores."""

    def _get_storage_backend(self) -> str:
        return self._get_storage_backend_config().backend

    def _get_storage_backend_config(self) -> StorageBackendConfig:
        return get_plugin_config().storage_backend_config

    def _build_auth_store(
        self, user_storage_dir: Path, storage_backend_config: StorageBackendConfig
    ) -> MatrixFolderDataStore:
        namespace = build_folder_namespace(
            user_storage_dir, Path(self.config.store_path)
        )
        backend = storage_backend_config.backend
        try:
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend=backend,
                json_filename_resolver=self._auth_json_filename,
                pgsql_dsn=storage_backend_config.pgsql_dsn,
                pgsql_schema=storage_backend_config.pgsql_schema,
                pgsql_table_prefix=storage_backend_config.pgsql_table_prefix,
            )
        except Exception as e:
            self._log(
                "info", f"Auth store backend {backend} init failed, fallback json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend="json",
                json_filename_resolver=self._auth_json_filename,
            )

    def _save_token_to_backend(self, store: MatrixFolderDataStore, data: dict) -> None:
        with self._token_backend_save_lock:
            store.upsert("auth", data)

    _token_backend_save_lock = threading.Lock()
