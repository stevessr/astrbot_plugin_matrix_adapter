"""
E2EE storage backend helpers.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from astrbot.api import logger

from ..storage_backend import MatrixFolderDataStore, StorageBackendConfig

JsonFilenameResolver = Callable[[str], str]


def build_e2ee_data_store(
    folder_path: Path,
    namespace_key: str,
    storage_backend_config: StorageBackendConfig,
    *,
    json_filename_resolver: JsonFilenameResolver,
    store_name: str = "store",
) -> MatrixFolderDataStore:
    """
    Build E2EE store with backend fallback.

    Falls back to json backend when sqlite/pgsql init fails.
    """
    normalized = storage_backend_config.backend
    try:
        return MatrixFolderDataStore(
            folder_path=folder_path,
            namespace_key=namespace_key,
            backend=normalized,
            json_filename_resolver=json_filename_resolver,
            pgsql_dsn=storage_backend_config.pgsql_dsn,
            pgsql_schema=storage_backend_config.pgsql_schema,
            pgsql_table_prefix=storage_backend_config.pgsql_table_prefix,
        )
    except Exception as e:
        logger.warning(
            f"初始化 E2EE {store_name} 存储后端 {normalized} 失败，回退 json: {e}"
        )
        return MatrixFolderDataStore(
            folder_path=folder_path,
            namespace_key=namespace_key,
            backend="json",
            json_filename_resolver=json_filename_resolver,
        )
