"""PostgreSQL table initialization."""


class PgSQLBackendTableMixin:
    """Ensure the backend table exists."""

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


__all__ = ["PgSQLBackendTableMixin"]
