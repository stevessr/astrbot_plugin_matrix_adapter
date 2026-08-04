"""Media-cache index store initialization."""

from astrbot.api import logger

from ......config.plugin import get_plugin_config
from ......utils.media_cache_index import MediaCacheIndexStore


def _media_cache_index_filename() -> str:
    return "media_cache_index.sqlite3"


def _is_media_cache_index_persist_enabled(self) -> bool:
    try:
        return bool(get_plugin_config().media_cache_index_persist)
    except Exception:
        return True


def _initialize_media_cache_index_store(self) -> None:
    if not _is_media_cache_index_persist_enabled(self):
        return
    cache_dir = self._get_media_cache_dir()
    db_path = cache_dir / _media_cache_index_filename()
    try:
        self._media_cache_index_store = MediaCacheIndexStore(
            db_path=db_path,
            cache_dir=cache_dir,
        )
        self._heal_media_cache_index()
    except Exception as e:
        logger.warning(f"Failed to initialize media cache index store: {e}")
        self._media_cache_index_store = None
