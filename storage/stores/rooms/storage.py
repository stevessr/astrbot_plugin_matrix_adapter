"""Room storage backend construction operations."""

from astrbot.api import logger

from ...backend import MatrixFolderDataStore
from ...paths import MatrixStoragePaths


class MatrixRoomStorageMixin:
    """Build the backend used by the room member store."""

    @staticmethod
    def _json_filename(room_id: str) -> str:
        safe_room = MatrixStoragePaths.sanitize_username(room_id)
        if not safe_room:
            safe_room = "unknown"
        return f"{safe_room}.json"

    def _build_store(self) -> MatrixFolderDataStore:
        try:
            return MatrixFolderDataStore(
                folder_path=self._rooms_dir,
                namespace_key="rooms",
                backend=self._storage_backend,
                json_filename_resolver=self._json_filename,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化房间存储后端 {self._storage_backend} 失败，回退 json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=self._rooms_dir,
                namespace_key="rooms",
                backend="json",
                json_filename_resolver=self._json_filename,
            )
