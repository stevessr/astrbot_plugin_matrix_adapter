"""Cache-path construction and existing-file lookup."""

from pathlib import Path

from astrbot.api import logger


class MatrixReceiverMediaCacheBuildMixin:
    """Build cache paths and locate already-cached media files."""

    def _find_existing_media_cache_file(
        self, cache_key: str, cache_dir: Path
    ) -> Path | None:
        cached = self._media_cache_index.get(cache_key)
        if cached:
            try:
                size_bytes = cached.stat().st_size
                if cached.is_file() and size_bytes > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, cached, size_bytes=size_bytes
                    )
                    return cached
            except Exception:
                pass
            self._remove_media_cache_index_entry(cache_key)

        if self._media_cache_index_store:
            try:
                indexed_path = self._media_cache_index_store.get(cache_key)
                if indexed_path and indexed_path.is_file():
                    size_bytes = indexed_path.stat().st_size
                    if size_bytes > 0:
                        self._upsert_media_cache_index_entry(
                            cache_key, indexed_path, size_bytes=size_bytes
                        )
                        return indexed_path
                if indexed_path:
                    self._remove_media_cache_index_entry(cache_key)
            except Exception as e:
                logger.debug(f"Failed to restore media cache index entry: {e}")

        try:
            for path in cache_dir.glob(f"{cache_key}*"):
                if path.is_file() and path.stat().st_size > 0:
                    self._upsert_media_cache_index_entry(
                        cache_key, path, size_bytes=path.stat().st_size
                    )
                    return path
        except Exception:
            return None
        return None

    def _build_media_cache_path(
        self, mxc_url: str, filename: str | None = None, mimetype: str | None = None
    ) -> Path:
        cache_key = self._media_cache_key(mxc_url)
        cache_dir = self._get_media_cache_dir()
        existing = self._find_existing_media_cache_file(cache_key, cache_dir)
        if existing:
            return existing

        ext = self._guess_media_ext(filename, mimetype)
        return cache_dir / f"{cache_key}{ext}"
