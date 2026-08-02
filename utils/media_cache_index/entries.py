"""Media cache index entry lookup and update operations."""

import time
from pathlib import Path


class MediaCacheIndexEntriesMixin:
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
