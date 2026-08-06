"""PostgreSQL record write and delete operations."""

import json
from typing import Any


class PgSQLBackendWriteMixin:
    """Write and delete records in the backend table."""

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


__all__ = ["PgSQLBackendWriteMixin"]
