"""SQLite database initialization for the media cache index."""

import sqlite3
import threading
from pathlib import Path


class MediaCacheIndexDatabaseMixin:
    def __init__(self, db_path: str | Path, cache_dir: str | Path):
        self._db_path = Path(db_path)
        self._cache_dir = Path(cache_dir)
        self._lock = threading.Lock()
        self._ensure_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5.0)

    def _ensure_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS media_cache_index (
                        cache_key TEXT PRIMARY KEY,
                        rel_path TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        accessed_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_media_cache_index_accessed_at
                    ON media_cache_index(accessed_at)
                    """
                )
                conn.commit()
