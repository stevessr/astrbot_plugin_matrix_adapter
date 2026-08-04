"""Storage path and backend configuration for the E2EE manager."""

from pathlib import Path

from ......storage.backend import (
    build_folder_namespace as _DEFAULT_BUILD_FOLDER_NAMESPACE,
)
from ......storage.paths import MatrixStoragePaths as _DEFAULT_MATRIX_STORAGE_PATHS
from ...compat import resolve_manager_symbol, resolve_plugin_config


class E2EEManagerCoreInitializationConstructorStorageMixin:
    def _init_storage_paths(
        self,
        store_path: str | Path,
        homeserver: str,
        user_id: str,
    ) -> None:
        self._store_base_path = Path(store_path)
        storage_paths = resolve_manager_symbol(
            "MatrixStoragePaths",
            _DEFAULT_MATRIX_STORAGE_PATHS,
        )
        self.store_path = storage_paths.get_user_storage_dir(
            str(self._store_base_path), homeserver, user_id
        )
        build_namespace = resolve_manager_symbol(
            "build_folder_namespace",
            _DEFAULT_BUILD_FOLDER_NAMESPACE,
        )
        self._store_namespace = build_namespace(self.store_path, self._store_base_path)

        # Ensure the directory exists
        storage_paths.ensure_directory(self.store_path, treat_as_file=False)

    def _init_storage_config(self) -> None:
        plugin_config = resolve_plugin_config()
        self.storage_backend_config = plugin_config.storage_backend_config
        self.data_storage_backend = self.storage_backend_config.backend
        self.pgsql_dsn = self.storage_backend_config.pgsql_dsn
        self.pgsql_schema = self.storage_backend_config.pgsql_schema
        self.pgsql_table_prefix = self.storage_backend_config.pgsql_table_prefix
