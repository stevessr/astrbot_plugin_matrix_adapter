"""Media-cache garbage collection."""

import time

from astrbot.api import logger

from ......config.plugin import get_plugin_config


class MatrixReceiverMediaCacheGcMixin:
    """Garbage-collect stale files from the media cache."""

    def gc_media_cache(self, older_than_days: int | None = None) -> int:
        """清理媒体缓存，返回删除文件数"""
        cache_dir = self._get_media_cache_dir()
        if older_than_days is None:
            older_than_days = get_plugin_config().media_cache_gc_days

        if older_than_days <= 0:
            return 0

        cutoff = time.time() - older_than_days * 86400
        removed = 0

        for path in cache_dir.iterdir():
            if not path.is_file():
                continue
            if (
                self._media_cache_index_store
                and self._media_cache_index_store.is_index_file(path)
            ):
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
                    cache_key = self._extract_cache_key_from_path(path)
                    self._remove_media_cache_index_entry(cache_key, path=path)
            except Exception as e:
                logger.debug(f"清理媒体缓存失败：{path} ({e})")

        return removed
