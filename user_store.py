"""
Matrix user profile store for interacted accounts.

Stores display name and avatar URL under plugin data dir / users.
"""

from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from .plugin_config import get_plugin_config
from .storage_backend import MatrixFolderDataStore, StorageBackendConfig
from .storage_paths import MatrixStoragePaths


class MatrixUserStore:
    """Persist interacted user profiles (display name + avatar URL)."""

    def __init__(
        self,
        data_dir: Path | None = None,
        storage_backend_config: StorageBackendConfig | None = None,
        storage_backend: str | None = None,
        pgsql_dsn: str | None = None,
        pgsql_schema: str | None = None,
        pgsql_table_prefix: str | None = None,
    ) -> None:
        if data_dir is None:
            try:
                data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
            except Exception:
                data_dir = Path("./data/astrbot_plugin_matrix_adapter")
        self._users_dir = data_dir / "users"
        self._users_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}

        plugin_cfg = get_plugin_config()
        if storage_backend_config is not None:
            self._storage_backend_config = storage_backend_config
        elif any(
            value is not None
            for value in (
                storage_backend,
                pgsql_dsn,
                pgsql_schema,
                pgsql_table_prefix,
            )
        ):
            self._storage_backend_config = StorageBackendConfig.create(
                backend=storage_backend or plugin_cfg.data_storage_backend,
                pgsql_dsn=(
                    pgsql_dsn if pgsql_dsn is not None else plugin_cfg.pgsql_dsn
                ),
                pgsql_schema=pgsql_schema or plugin_cfg.pgsql_schema,
                pgsql_table_prefix=pgsql_table_prefix or plugin_cfg.pgsql_table_prefix,
            )
        else:
            self._storage_backend_config = plugin_cfg.storage_backend_config
        self._storage_backend = self._storage_backend_config.backend
        self._pgsql_dsn = self._storage_backend_config.pgsql_dsn
        self._pgsql_schema = self._storage_backend_config.pgsql_schema
        self._pgsql_table_prefix = self._storage_backend_config.pgsql_table_prefix

        self._store = self._build_store()

    @staticmethod
    def _json_filename(user_id: str) -> str:
        safe_user = MatrixStoragePaths.sanitize_username(user_id)
        if not safe_user:
            safe_user = "unknown"
        return f"{safe_user}.json"

    def _build_store(self) -> MatrixFolderDataStore:
        try:
            return MatrixFolderDataStore(
                folder_path=self._users_dir,
                namespace_key="users",
                backend=self._storage_backend,
                json_filename_resolver=self._json_filename,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化用户存储后端 {self._storage_backend} 失败，回退 json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=self._users_dir,
                namespace_key="users",
                backend="json",
                json_filename_resolver=self._json_filename,
            )

    def get(self, user_id: str) -> dict[str, Any] | None:
        if not user_id:
            return None
        if user_id in self._cache:
            return self._cache[user_id]
        try:
            data = self._store.get(user_id)
            if isinstance(data, dict):
                self._cache[user_id] = data
                return data
        except Exception as e:
            logger.debug(f"Failed to read user profile {user_id}: {e}")
        return None

    def upsert(self, user_id: str, display_name: str | None, avatar_url: str | None):
        if not user_id:
            return
        existing = self.get(user_id) or {"user_id": user_id}
        updated = False

        if display_name and display_name != existing.get("display_name"):
            existing["display_name"] = display_name
            updated = True
        if avatar_url and avatar_url != existing.get("avatar_url"):
            existing["avatar_url"] = avatar_url
            updated = True

        if not updated:
            return

        try:
            self._store.upsert(user_id, existing)
            self._cache[user_id] = existing
        except Exception as e:
            logger.debug(f"Failed to save user profile {user_id}: {e}")
