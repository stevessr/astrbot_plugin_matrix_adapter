"""Device storage backend construction."""

from astrbot.api import logger

from ....backend import MatrixFolderDataStore


class MatrixDevicePersistenceBackendMixin:
    """Build and fall back the device storage backend."""

    @staticmethod
    def _device_json_filename(_: str) -> str:
        return "device_info.json"

    def _build_device_store(self, namespace: str) -> MatrixFolderDataStore:
        try:
            return MatrixFolderDataStore(
                folder_path=self.user_store_path,
                namespace_key=namespace,
                backend=self._storage_backend,
                json_filename_resolver=self._device_json_filename,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化设备存储后端 {self._storage_backend} 失败，回退 json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=self.user_store_path,
                namespace_key=namespace,
                backend="json",
                json_filename_resolver=self._device_json_filename,
            )


__all__ = ["MatrixDevicePersistenceBackendMixin"]
