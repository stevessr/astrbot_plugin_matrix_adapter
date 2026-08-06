"""PostgreSQL connection management."""

from ..common import normalize_pg_identifier


class PgSQLBackendConnectionMixin:
    """Manage the PostgreSQL connection lifecycle."""

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


__all__ = ["PgSQLBackendConnectionMixin"]
