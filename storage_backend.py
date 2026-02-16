"""
Matrix data storage backend facade.

This module keeps the public API stable while delegating each backend
implementation to independent files under `storage_backends/`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from astrbot.api import logger

from .storage_backends import (
    JsonBackend,
    PgSQLBackend,
    SQLiteBackend,
    build_folder_namespace,
    build_pg_table_name,
    normalize_storage_backend,
)
from .storage_paths import MatrixStoragePaths

JsonFilenameResolver = Callable[[str], str]

__all__ = [
    "normalize_storage_backend",
    "build_pg_table_name",
    "build_folder_namespace",
    "StorageBackendConfig",
    "MatrixFolderDataStore",
]


@dataclass(frozen=True)
class StorageBackendConfig:
    """Runtime storage backend config shared across components."""

    backend: str = "json"
    pgsql_dsn: str = ""
    pgsql_schema: str = "public"
    pgsql_table_prefix: str = "matrix_store"

    @classmethod
    def create(
        cls,
        *,
        backend: str | None = None,
        pgsql_dsn: str | None = None,
        pgsql_schema: str | None = None,
        pgsql_table_prefix: str | None = None,
    ) -> StorageBackendConfig:
        return cls(
            backend=normalize_storage_backend(backend),
            pgsql_dsn=(pgsql_dsn or "").strip(),
            pgsql_schema=(pgsql_schema or "public").strip() or "public",
            pgsql_table_prefix=(pgsql_table_prefix or "matrix_store").strip()
            or "matrix_store",
        )


class MatrixFolderDataStore:
    """
    Multi-backend key-value store scoped to one folder namespace.

    For json backend: key -> `<sanitized_key>.json` (or custom filename resolver)
    For sqlite backend: key -> row in `<folder>/<folder_name>.db`
    For pgsql backend: key -> row in one table mapped from folder namespace
    """

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

    def get(self, record_key: str) -> Any | None:
        """Read one record from selected backend."""
        if not record_key:
            return None

        data = self._backend_impl.get(record_key)
        if data is not None:
            return data

        # Non-json backend: fallback to legacy json files and auto-migrate.
        if self.backend != "json":
            legacy = self._json_backend.get(record_key)
            if legacy is not None:
                try:
                    self._backend_impl.upsert(record_key, legacy)
                except Exception as e:
                    logger.debug(
                        f"Failed to migrate legacy json for {self.namespace_key}:{record_key}: {e}"
                    )
            return legacy

        return None

    def upsert(self, record_key: str, data: Any) -> None:
        """Create or update one record."""
        if not record_key:
            return
        self._backend_impl.upsert(record_key, data)

    def delete(self, record_key: str) -> None:
        """Delete one record."""
        if not record_key:
            return
        self._backend_impl.delete(record_key)
