"""
Persistent SQLite index for Matrix media cache files.
"""

import sqlite3
import threading
import time
from pathlib import Path

from astrbot.api import logger


class MediaCacheIndexStore:
    """SQLite-backed media cache index."""

    def __init__(self, db_path: str | Path, cache_dir: str | Path):
        self._db_path = Path(db_path)
        self._cache_dir = Path(cache_dir)
        self._lock = threading.Lock()
        self._ensure_db()

    @property
    def db_path(self) -> Path:
        return self._db_path

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

    def _to_rel_path(self, path: Path) -> str:
        resolved_path = path.resolve()
        resolved_cache_dir = self._cache_dir.resolve()
        try:
            return resolved_path.relative_to(resolved_cache_dir).as_posix()
        except ValueError:
            return resolved_path.as_posix()

    def _to_abs_path(self, stored_path: str) -> Path:
        candidate = Path(stored_path)
        if candidate.is_absolute():
            return candidate
        return (self._cache_dir / candidate).resolve()

    def get(self, cache_key: str) -> Path | None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT rel_path FROM media_cache_index WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()
        if not row:
            return None
        stored_path = row[0]
        if not isinstance(stored_path, str):
            return None
        return self._to_abs_path(stored_path)

    def list_entries(self) -> list[tuple[str, Path]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT cache_key, rel_path FROM media_cache_index"
                ).fetchall()
        entries: list[tuple[str, Path]] = []
        for row in rows:
            if not isinstance(row, tuple) or len(row) != 2:
                continue
            cache_key, rel_path = row
            if not isinstance(cache_key, str) or not isinstance(rel_path, str):
                continue
            entries.append((cache_key, self._to_abs_path(rel_path)))
        return entries

    def upsert(
        self,
        cache_key: str,
        path: Path,
        *,
        size_bytes: int | None = None,
    ) -> None:
        now = time.time()
        rel_path = self._to_rel_path(path)
        normalized_size = 0
        if size_bytes is not None:
            try:
                normalized_size = max(0, int(size_bytes))
            except (TypeError, ValueError):
                normalized_size = 0
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO media_cache_index (
                        cache_key, rel_path, size_bytes, accessed_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        rel_path=excluded.rel_path,
                        size_bytes=excluded.size_bytes,
                        accessed_at=excluded.accessed_at,
                        updated_at=excluded.updated_at
                    """,
                    (cache_key, rel_path, normalized_size, now, now),
                )
                conn.commit()

    def touch(self, cache_key: str) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE media_cache_index
                    SET accessed_at = ?, updated_at = ?
                    WHERE cache_key = ?
                    """,
                    (now, now, cache_key),
                )
                conn.commit()

    def remove(self, cache_key: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM media_cache_index WHERE cache_key = ?",
                    (cache_key,),
                )
                conn.commit()

    def remove_by_path(self, path: Path) -> None:
        rel_path = self._to_rel_path(path)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM media_cache_index WHERE rel_path = ?",
                    (rel_path,),
                )
                conn.commit()

    def is_index_file(self, path: Path) -> bool:
        db_name = self._db_path.name
        name = path.name
        return name == db_name or name.startswith(f"{db_name}-")

    def safe_remove(self, cache_key: str) -> None:
        try:
            self.remove(cache_key)
        except Exception as e:
            logger.debug(f"Failed to remove media cache index entry {cache_key}: {e}")
