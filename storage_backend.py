"""
Matrix data storage backend helpers.

Supports:
- json: one json file per key
- sqlite: one sqlite db per folder
- pgsql: one table per folder namespace
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from astrbot.api import logger

from .storage_paths import MatrixStoragePaths

JsonFilenameResolver = Callable[[str], str]

_STORAGE_BACKEND_ALIASES = {
    "json": "json",
    "sqlite": "sqlite",
    "pgsql": "pgsql",
    "postgres": "pgsql",
    "postgresql": "pgsql",
}


def normalize_storage_backend(value: str | None) -> str:
    """Normalize storage backend value to json/sqlite/pgsql."""
    if not isinstance(value, str):
        return "json"
    normalized = value.strip().lower()
    return _STORAGE_BACKEND_ALIASES.get(normalized, "json")


def _sanitize_pg_identifier(value: str, fallback: str) -> str:
    identifier = re.sub(r"[^a-zA-Z0-9_]+", "_", (value or "").strip()).strip("_")
    if not identifier:
        identifier = fallback
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier.lower()


def build_pg_table_name(namespace_key: str, prefix: str = "matrix_store") -> str:
    """
    Build a valid PostgreSQL table name from namespace.

    PostgreSQL identifier length limit is 63 bytes.
    """
    safe_prefix = _sanitize_pg_identifier(prefix, "matrix_store")
    safe_namespace = _sanitize_pg_identifier(namespace_key.replace("/", "_"), "store")
    digest = hashlib.sha1(namespace_key.encode("utf-8")).hexdigest()[:8]

    base = f"{safe_prefix}_{safe_namespace}"
    max_base_len = 63 - len(digest) - 1
    if len(base) > max_base_len:
        base = base[:max_base_len].rstrip("_")
    if not base:
        base = safe_prefix
    return f"{base}_{digest}"


def build_folder_namespace(folder_path: Path, base_path: Path | None = None) -> str:
    """Build stable namespace key for one folder."""
    if base_path is not None:
        try:
            return folder_path.relative_to(base_path).as_posix()
        except Exception:
            pass
    return folder_path.as_posix()


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
        db_filename = sqlite_db_filename or f"{self.folder_path.name or 'store'}.db"
        self._sqlite_db_path = self.folder_path / db_filename

        self._pgsql_dsn = (pgsql_dsn or "").strip()
        self._pgsql_schema = _sanitize_pg_identifier(pgsql_schema, "public")
        self._pgsql_table_name = build_pg_table_name(
            self.namespace_key, pgsql_table_prefix
        )

        if self.backend == "sqlite":
            self._ensure_sqlite_table()
        elif self.backend == "pgsql":
            if not self._pgsql_dsn:
                raise ValueError("pgsql backend requires non-empty DSN")
            self._ensure_pgsql_table()

    @staticmethod
    def _default_json_filename(record_key: str) -> str:
        safe_key = MatrixStoragePaths.sanitize_username(record_key)
        if not safe_key:
            safe_key = "unknown"
        return f"{safe_key}.json"

    def _json_path(self, record_key: str) -> Path:
        filename = self._json_filename_resolver(record_key)
        return self.folder_path / filename

    def get(self, record_key: str) -> Any | None:
        """Read one record from selected backend."""
        if not record_key:
            return None

        if self.backend == "json":
            return self._read_json(record_key)

        if self.backend == "sqlite":
            data = self._read_sqlite(record_key)
        elif self.backend == "pgsql":
            data = self._read_pgsql(record_key)
        else:
            data = None

        if data is not None:
            return data

        # Fallback to legacy json files and auto-migrate.
        legacy = self._read_json(record_key)
        if legacy is not None:
            try:
                self._write_backend_record(record_key, legacy)
            except Exception as e:
                logger.debug(
                    f"Failed to migrate legacy json for {self.namespace_key}:{record_key}: {e}"
                )
        return legacy

    def upsert(self, record_key: str, data: Any) -> None:
        """Create or update one record."""
        if not record_key:
            return
        self._write_backend_record(record_key, data)

    def delete(self, record_key: str) -> None:
        """Delete one record."""
        if not record_key:
            return
        if self.backend == "json":
            path = self._json_path(record_key)
            if path.exists():
                path.unlink()
            return
        if self.backend == "sqlite":
            self._delete_sqlite(record_key)
            return
        if self.backend == "pgsql":
            self._delete_pgsql(record_key)
            return

    def _read_json(self, record_key: str) -> Any | None:
        path = self._json_path(record_key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(
                f"Failed to read json record {self.namespace_key}:{record_key}: {e}"
            )
            return None

    def _write_backend_record(self, record_key: str, data: Any) -> None:
        if self.backend == "json":
            self._write_json(record_key, data)
        elif self.backend == "sqlite":
            self._write_sqlite(record_key, data)
        elif self.backend == "pgsql":
            self._write_pgsql(record_key, data)
        else:
            self._write_json(record_key, data)

    def _write_json(self, record_key: str, data: Any) -> None:
        path = self._json_path(record_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _get_sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._sqlite_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_sqlite_table(self) -> None:
        with self._get_sqlite_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    record_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def _read_sqlite(self, record_key: str) -> Any | None:
        try:
            with self._get_sqlite_conn() as conn:
                row = conn.execute(
                    "SELECT payload FROM records WHERE record_key = ?",
                    (record_key,),
                ).fetchone()
            if not row:
                return None
            return json.loads(row["payload"])
        except Exception as e:
            logger.debug(
                f"Failed to read sqlite record {self.namespace_key}:{record_key}: {e}"
            )
            return None

    def _write_sqlite(self, record_key: str, data: Any) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        with self._get_sqlite_conn() as conn:
            conn.execute(
                """
                INSERT INTO records (record_key, payload, updated_at)
                VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER))
                ON CONFLICT(record_key) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (record_key, payload),
            )
            conn.commit()

    def _delete_sqlite(self, record_key: str) -> None:
        with self._get_sqlite_conn() as conn:
            conn.execute(
                "DELETE FROM records WHERE record_key = ?",
                (record_key,),
            )
            conn.commit()

    def _get_pgsql_conn(self):
        try:
            import psycopg
        except ImportError as e:
            raise RuntimeError(
                "psycopg is required for pgsql backend. Install `psycopg[binary]`."
            ) from e
        return psycopg.connect(self._pgsql_dsn, autocommit=True)

    def _pgsql_table_sql(self):
        from psycopg import sql

        return sql.SQL("{}.{}").format(
            sql.Identifier(self._pgsql_schema),
            sql.Identifier(self._pgsql_table_name),
        )

    def _ensure_pgsql_table(self) -> None:
        from psycopg import sql

        query = sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                record_key TEXT PRIMARY KEY,
                payload JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        ).format(self._pgsql_table_sql())
        with self._get_pgsql_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query)

    def _read_pgsql(self, record_key: str) -> Any | None:
        from psycopg import sql

        query = sql.SQL("SELECT payload::text FROM {} WHERE record_key = %s").format(
            self._pgsql_table_sql()
        )
        try:
            with self._get_pgsql_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (record_key,))
                    row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
        except Exception as e:
            logger.debug(
                f"Failed to read pgsql record {self.namespace_key}:{record_key}: {e}"
            )
            return None

    def _write_pgsql(self, record_key: str, data: Any) -> None:
        from psycopg import sql

        query = sql.SQL(
            """
            INSERT INTO {} (record_key, payload, updated_at)
            VALUES (%s, %s::jsonb, NOW())
            ON CONFLICT (record_key) DO UPDATE SET
                payload = EXCLUDED.payload,
                updated_at = EXCLUDED.updated_at
            """
        ).format(self._pgsql_table_sql())
        payload = json.dumps(data, ensure_ascii=False)
        with self._get_pgsql_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (record_key, payload))

    def _delete_pgsql(self, record_key: str) -> None:
        from psycopg import sql

        query = sql.SQL("DELETE FROM {} WHERE record_key = %s").format(
            self._pgsql_table_sql()
        )
        with self._get_pgsql_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (record_key,))
