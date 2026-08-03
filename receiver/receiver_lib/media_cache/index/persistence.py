"""Persistent media-cache index lifecycle operations."""

from pathlib import Path

from astrbot.api import logger

from .....config.plugin import get_plugin_config
from .....utils.media_cache_index import MediaCacheIndexStore


class MatrixReceiverMediaCachePersistenceMixin:
    """Initialize, heal, and update the persistent media-cache index."""

    @staticmethod
    def _media_cache_index_filename() -> str:
        return "media_cache_index.sqlite3"

    def _is_media_cache_index_persist_enabled(self) -> bool:
        try:
            return bool(get_plugin_config().media_cache_index_persist)
        except Exception:
            return True

    def _initialize_media_cache_index_store(self) -> None:
        if not self._is_media_cache_index_persist_enabled():
            return
        cache_dir = self._get_media_cache_dir()
        db_path = cache_dir / self._media_cache_index_filename()
        try:
            self._media_cache_index_store = MediaCacheIndexStore(
                db_path=db_path,
                cache_dir=cache_dir,
            )
            self._heal_media_cache_index()
        except Exception as e:
            logger.warning(f"Failed to initialize media cache index store: {e}")
            self._media_cache_index_store = None

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
                if (
                    previous_mtime is not None
                    and previous_mtime >= stat_result.st_mtime
                ):
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
        self._upsert_media_cache_index_entry(
            cache_key, cache_path, size_bytes=size_bytes
        )
