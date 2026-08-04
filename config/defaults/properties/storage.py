"""Default-backed configuration properties: storage backends."""

from ....storage.backend import StorageBackendConfig


class PluginConfigDefaultsStorageMixin:
    """存储后端相关的默认配置属性。"""

    @property
    def data_storage_backend(self) -> str:
        """数据存储后端（json/sqlite/pgsql）"""
        return self._data_storage_backend

    @property
    def pgsql_dsn(self) -> str:
        """PostgreSQL DSN"""
        return self._pgsql_dsn

    @property
    def pgsql_schema(self) -> str:
        """PostgreSQL schema"""
        return self._pgsql_schema

    @property
    def pgsql_table_prefix(self) -> str:
        """PostgreSQL 表名前缀"""
        return self._pgsql_table_prefix

    @property
    def e2ee_store_max_pending_writes(self) -> int:
        """E2EE store async persistence pending queue limit"""
        return self._e2ee_store_max_pending_writes

    @property
    def storage_backend_config(self) -> StorageBackendConfig:
        """运行时固定存储后端配置对象。"""
        return self._storage_backend_config
