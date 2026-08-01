"""
PostgreSQL storage backend.
"""

from __future__ import annotations

import json
from typing import Any

from astrbot.api import logger

from .common import normalize_pg_identifier


class PgSQLBackend:
    """One PostgreSQL table per folder namespace."""

    def __init__(self, dsn: str, schema: str, table_name: str) -> None:
        self.dsn = (dsn or "").strip()
        if not self.dsn:
            raise ValueError("pgsql backend requires non-empty DSN")
        self.schema = normalize_pg_identifier(schema, "public")
        self.table_name = normalize_pg_identifier(table_name, "matrix_store")
        self._ensure_table()

    def _conn(self):
        try:
            import psycopg
        except ImportError as e:
            raise RuntimeError(
                "psycopg is required for pgsql backend. Install `psycopg[binary]`."
            ) from e
        return psycopg.connect(self.dsn, autocommit=True)

    def _table_sql(self):
        from psycopg import sql

        return sql.SQL("{}.{}").format(
            sql.Identifier(self.schema),
            sql.Identifier(self.table_name),
        )

    def _ensure_table(self) -> None:
        from psycopg import sql

        query = sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                record_key TEXT PRIMARY KEY,
                payload JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        ).format(self._table_sql())
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query)

    def get(self, record_key: str) -> Any | None:
        from psycopg import sql

        query = sql.SQL("SELECT payload::text FROM {} WHERE record_key = %s").format(
            self._table_sql()
        )
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (record_key,))
                    row = cur.fetchone()
            if not row:
                return None
            payload_text = row[0]
            if not isinstance(payload_text, str):
                logger.debug(
                    f"Invalid pgsql payload type for key {record_key}: {type(payload_text)}"
                )
                return None
            try:
                return json.loads(payload_text)
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid pgsql JSON payload for key {record_key}: {e}")
                return None
        except Exception as e:
            logger.debug(f"Failed to read pgsql record {record_key}: {e}")
            return None

    def upsert(self, record_key: str, data: Any) -> None:
        from psycopg import sql

        query = sql.SQL(
            """
            INSERT INTO {} (record_key, payload, updated_at)
            VALUES (%s, %s::jsonb, NOW())
            ON CONFLICT (record_key) DO UPDATE SET
                payload = EXCLUDED.payload,
                updated_at = EXCLUDED.updated_at
            """
        ).format(self._table_sql())
        payload = json.dumps(data, ensure_ascii=False)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (record_key, payload))

    def delete(self, record_key: str) -> None:
        from psycopg import sql

        query = sql.SQL("DELETE FROM {} WHERE record_key = %s").format(
            self._table_sql()
        )
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (record_key,))
