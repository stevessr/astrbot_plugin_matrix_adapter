"""PostgreSQL record read operations."""

import json
from typing import Any

from astrbot.api import logger


class PgSQLBackendReadMixin:
    """Read records from the backend table."""

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


__all__ = ["PgSQLBackendReadMixin"]
