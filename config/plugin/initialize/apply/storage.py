"""Plugin storage-backend configuration extraction and validation."""

from .....storage.backend import StorageBackendConfig, normalize_storage_backend
from ....defaults import (
    _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
    _normalize_non_negative_int,
    _normalize_pgsql_schema,
    _normalize_pgsql_table_prefix,
)


class PluginConfigInitializationStorageMixin:
    """Apply storage-backend settings from the config dictionary."""

    def _initialize_storage_settings(self, config: dict) -> None:
        # 数据存储后端配置
        self._data_storage_backend = normalize_storage_backend(
            config.get("matrix_data_storage_backend", "json")
        )
        pgsql_obj = config.get("matrix_pgsql")
        pgsql_dsn = None
        pgsql_schema = None
        pgsql_table_prefix = None
        if isinstance(pgsql_obj, dict):
            pgsql_dsn = pgsql_obj.get("dsn")
            pgsql_schema = pgsql_obj.get("schema")
            pgsql_table_prefix = pgsql_obj.get("table_prefix")

        # 兼容旧配置：matrix_pgsql_dsn / matrix_pgsql_schema / matrix_pgsql_table_prefix
        if pgsql_dsn is None:
            pgsql_dsn = config.get("matrix_pgsql_dsn", "")
        if pgsql_schema is None:
            pgsql_schema = config.get("matrix_pgsql_schema")
        if pgsql_table_prefix is None:
            pgsql_table_prefix = config.get("matrix_pgsql_table_prefix")

        self._pgsql_dsn = str(pgsql_dsn or "").strip()
        self._pgsql_schema = _normalize_pgsql_schema(pgsql_schema)
        self._pgsql_table_prefix = _normalize_pgsql_table_prefix(pgsql_table_prefix)
        self._e2ee_store_max_pending_writes = _normalize_non_negative_int(
            config.get("matrix_e2ee_store_max_pending_writes"),
            _DEFAULT_E2EE_STORE_MAX_PENDING_WRITES,
            min_value=1,
            config_key="matrix_e2ee_store_max_pending_writes",
        )

        if self._data_storage_backend == "pgsql" and not self._pgsql_dsn:
            raise ValueError(
                "matrix_data_storage_backend=pgsql requires matrix_pgsql.dsn "
                "(or legacy matrix_pgsql_dsn)"
            )

        self._storage_backend_config = StorageBackendConfig.create(
            backend=self._data_storage_backend,
            pgsql_dsn=self._pgsql_dsn,
            pgsql_schema=self._pgsql_schema,
            pgsql_table_prefix=self._pgsql_table_prefix,
        )
