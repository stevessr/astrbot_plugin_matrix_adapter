"""Matrix storage paths and backend implementations."""

from .backend import (
    MatrixFolderDataStore,
    StorageBackendConfig,
    build_folder_namespace,
    build_pg_table_name,
    normalize_storage_backend,
)
from .backends import JsonBackend, PgSQLBackend, SQLiteBackend
from .paths import MatrixStoragePaths

__all__ = [
    "MatrixStoragePaths",
    "StorageBackendConfig",
    "MatrixFolderDataStore",
    "normalize_storage_backend",
    "build_pg_table_name",
    "build_folder_namespace",
    "JsonBackend",
    "SQLiteBackend",
    "PgSQLBackend",
]
