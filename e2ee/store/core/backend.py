"""Storage backend construction for the crypto store."""

from ....config.plugin import get_plugin_config
from ...storage import build_e2ee_data_store


class CryptoStoreCoreBackendMixin:
    """Build the underlying data store."""

    def _init_storage_backend(self, namespace_key: str | None) -> None:
        # 创建存储目录
        self.store_path.mkdir(parents=True, exist_ok=True)
        self._namespace_key = namespace_key or self.store_path.as_posix()
        self.storage_backend_config = get_plugin_config().storage_backend_config
        self._data_store = build_e2ee_data_store(
            folder_path=self.store_path,
            namespace_key=self._namespace_key,
            storage_backend_config=self.storage_backend_config,
            json_filename_resolver=self._json_filename_resolver,
            store_name="crypto",
        )


__all__ = ["CryptoStoreCoreBackendMixin"]
