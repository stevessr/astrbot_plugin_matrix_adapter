"""Persistent media-cache index lifecycle operations."""

from pathlib import Path

from astrbot.api import logger

from ......config.plugin import get_plugin_config
from ......utils.media_cache_index import MediaCacheIndexStore
from .heal import _heal_media_cache_index
from .init import (
    _initialize_media_cache_index_store,
    _is_media_cache_index_persist_enabled,
    _media_cache_index_filename,
)
from .update import (
    _remove_media_cache_index_entry,
    _touch_cached_media_path,
    _upsert_media_cache_index_entry,
)


class MatrixReceiverMediaCachePersistenceMixin:
    """Initialize, heal, and update the persistent media-cache index."""


# Preserve direct-method access used by the parent index facade.
for _method in (
    _heal_media_cache_index,
    _initialize_media_cache_index_store,
    _is_media_cache_index_persist_enabled,
    _remove_media_cache_index_entry,
    _touch_cached_media_path,
    _upsert_media_cache_index_entry,
):
    setattr(MatrixReceiverMediaCachePersistenceMixin, _method.__name__, _method)
MatrixReceiverMediaCachePersistenceMixin._media_cache_index_filename = staticmethod(
    _media_cache_index_filename
)


__all__ = [
    "MatrixReceiverMediaCachePersistenceMixin",
    "MediaCacheIndexStore",
    "Path",
    "get_plugin_config",
    "logger",
]
