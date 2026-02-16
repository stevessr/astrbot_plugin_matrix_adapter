"""
SQLite storage backend.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from astrbot.api import logger


class SQLiteBackend:
    """One SQLite database file per folder namespace."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_table()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table(self) -> None:
        with self._conn() as conn:
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

    def get(self, record_key: str) -> Any | None:
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT payload FROM records WHERE record_key = ?",
                    (record_key,),
                ).fetchone()
            if not row:
                return None
            return json.loads(row["payload"])
        except Exception as e:
            logger.debug(f"Failed to read sqlite record {record_key}: {e}")
            return None

    def upsert(self, record_key: str, data: Any) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        with self._conn() as conn:
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

    def delete(self, record_key: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM records WHERE record_key = ?",
                (record_key,),
            )
            conn.commit()
