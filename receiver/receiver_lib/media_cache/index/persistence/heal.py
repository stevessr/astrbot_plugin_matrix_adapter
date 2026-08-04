"""Media-cache index healing on startup."""

from pathlib import Path

from astrbot.api import logger


def _heal_media_cache_index(self) -> None:
    if not self._media_cache_index_store:
        return

    cache_dir = self._get_media_cache_dir()
    disk_entries: dict[str, Path] = {}
    disk_sizes: dict[str, int] = {}
    disk_mtime: dict[str, float] = {}

    try:
        for path in cache_dir.iterdir():
            if not path.is_file():
                continue
            if self._media_cache_index_store.is_index_file(path):
                continue
            cache_key = self._extract_cache_key_from_path(path)
            if not cache_key:
                continue
            try:
                stat_result = path.stat()
            except Exception:
                continue
            if stat_result.st_size <= 0:
                continue
            previous_mtime = disk_mtime.get(cache_key)
            if previous_mtime is not None and previous_mtime >= stat_result.st_mtime:
                continue
            disk_entries[cache_key] = path
            disk_sizes[cache_key] = stat_result.st_size
            disk_mtime[cache_key] = stat_result.st_mtime
    except Exception as e:
        logger.debug(f"Failed to scan media cache directory for healing: {e}")
        return

    stale_removed = 0
    try:
        indexed_entries = self._media_cache_index_store.list_entries()
    except Exception as e:
        logger.debug(f"Failed to read media cache index entries for healing: {e}")
        indexed_entries = []

    for cache_key, _ in indexed_entries:
        if cache_key not in disk_entries:
            self._remove_media_cache_index_entry(cache_key)
            stale_removed += 1

    repaired = 0
    for cache_key, cache_path in disk_entries.items():
        self._upsert_media_cache_index_entry(
            cache_key,
            cache_path,
            size_bytes=disk_sizes.get(cache_key),
        )
        repaired += 1

    if stale_removed > 0 or repaired > 0:
        logger.debug(
            "Healed media cache index on startup: "
            f"indexed={repaired}, removed_stale={stale_removed}"
        )
