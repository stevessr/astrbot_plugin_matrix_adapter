"""Media cache index removal operations."""

from pathlib import Path

from astrbot.api import logger


class MediaCacheIndexCleanupMixin:
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

    def safe_remove(self, cache_key: str) -> None:
        try:
            self.remove(cache_key)
        except Exception as e:
            logger.debug(f"Failed to remove media cache index entry {cache_key}: {e}")
