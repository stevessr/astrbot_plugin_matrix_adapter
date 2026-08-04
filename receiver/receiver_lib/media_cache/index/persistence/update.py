"""Media-cache index entry updates."""

from pathlib import Path

from astrbot.api import logger


def _remove_media_cache_index_entry(
    self, cache_key: str | None, path: Path | None = None
) -> None:
    if cache_key:
        self._media_cache_index.pop(cache_key, None)
    if not self._media_cache_index_store:
        return
    try:
        if cache_key:
            self._media_cache_index_store.safe_remove(cache_key)
        elif path is not None:
            self._media_cache_index_store.remove_by_path(path)
    except Exception as e:
        logger.debug(f"Failed to remove media cache index entry: {e}")


def _upsert_media_cache_index_entry(
    self, cache_key: str, cache_path: Path, *, size_bytes: int | None = None
) -> None:
    self._media_cache_index[cache_key] = cache_path
    if not self._media_cache_index_store:
        return
    try:
        self._media_cache_index_store.upsert(
            cache_key,
            cache_path,
            size_bytes=size_bytes,
        )
    except Exception as e:
        logger.debug(f"Failed to upsert media cache index entry: {e}")


def _touch_cached_media_path(self, cache_key: str | None, cache_path: Path) -> None:
    try:
        cache_path.touch()
    except Exception:
        pass

    if cache_key is None:
        cache_key = self._extract_cache_key_from_path(cache_path)
    if cache_key is None:
        return

    try:
        size_bytes = cache_path.stat().st_size
    except Exception:
        size_bytes = None
    self._upsert_media_cache_index_entry(cache_key, cache_path, size_bytes=size_bytes)
