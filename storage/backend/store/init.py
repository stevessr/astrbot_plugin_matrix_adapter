"""Folder-scoped data store construction."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ...backends import (
    JsonBackend,
    PgSQLBackend,
    SQLiteBackend,
    build_pg_table_name,
    normalize_storage_backend,
)
from ...paths import MatrixStoragePaths

JsonFilenameResolver = Callable[[str], str]


class MatrixFolderDataStoreInitMixin:
    """Construct the folder-scoped multi-backend data store."""

    def __init__(
        self,
        folder_path: Path,
        namespace_key: str,
        backend: str = "json",
        *,
        json_filename_resolver: JsonFilenameResolver | None = None,
        sqlite_db_filename: str | None = None,
        pgsql_dsn: str | None = None,
        pgsql_schema: str = "public",
        pgsql_table_prefix: str = "matrix_store",
    ) -> None:
        self.folder_path = Path(folder_path)
        self.folder_path.mkdir(parents=True, exist_ok=True)

        self.namespace_key = namespace_key or self.folder_path.name
        self.backend = normalize_storage_backend(backend)

        self._json_filename_resolver = (
            json_filename_resolver or self._default_json_filename
        )
        self._json_backend = JsonBackend(self.folder_path, self._json_filename_resolver)

        db_filename = sqlite_db_filename or f"{self.folder_path.name or 'store'}.db"

        if self.backend == "sqlite":
            self._backend_impl = SQLiteBackend(self.folder_path / db_filename)
        elif self.backend == "pgsql":
            table_name = build_pg_table_name(self.namespace_key, pgsql_table_prefix)
            self._backend_impl = PgSQLBackend(pgsql_dsn or "", pgsql_schema, table_name)
        else:
            self._backend_impl = self._json_backend

    @staticmethod
    def _default_json_filename(record_key: str) -> str:
        safe_key = MatrixStoragePaths.sanitize_username(record_key)
        if not safe_key:
            safe_key = "unknown"
        return f"{safe_key}.json"


__all__ = ["MatrixFolderDataStoreInitMixin"]
