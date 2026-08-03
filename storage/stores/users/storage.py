"""User storage backend construction operations."""

from astrbot.api import logger

from ...backend import MatrixFolderDataStore
from ...paths import MatrixStoragePaths


class MatrixUserStorageMixin:
    """Build the backend used by the interacted-user store."""

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
