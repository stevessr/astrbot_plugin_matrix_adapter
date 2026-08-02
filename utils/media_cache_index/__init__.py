"""Composable persistent SQLite index for Matrix media cache files."""

import sqlite3
import threading
import time
from pathlib import Path

from astrbot.api import logger

from .cleanup import MediaCacheIndexCleanupMixin
from .database import MediaCacheIndexDatabaseMixin
from .entries import MediaCacheIndexEntriesMixin
from .paths import MediaCacheIndexPathsMixin


class MediaCacheIndexStore(
    MediaCacheIndexDatabaseMixin,
    MediaCacheIndexPathsMixin,
    MediaCacheIndexEntriesMixin,
    MediaCacheIndexCleanupMixin,
):
    """SQLite-backed media cache index."""

    pass


# Preserve direct method and property attributes exposed by the former store.
MediaCacheIndexStore.__init__ = MediaCacheIndexDatabaseMixin.__dict__["__init__"]
MediaCacheIndexStore.db_path = MediaCacheIndexPathsMixin.__dict__["db_path"]
MediaCacheIndexStore._connect = MediaCacheIndexDatabaseMixin.__dict__["_connect"]
MediaCacheIndexStore._ensure_db = MediaCacheIndexDatabaseMixin.__dict__["_ensure_db"]
MediaCacheIndexStore._to_rel_path = MediaCacheIndexPathsMixin.__dict__["_to_rel_path"]
MediaCacheIndexStore._to_abs_path = MediaCacheIndexPathsMixin.__dict__["_to_abs_path"]
MediaCacheIndexStore.get = MediaCacheIndexEntriesMixin.__dict__["get"]
MediaCacheIndexStore.list_entries = MediaCacheIndexEntriesMixin.__dict__["list_entries"]
MediaCacheIndexStore.upsert = MediaCacheIndexEntriesMixin.__dict__["upsert"]
MediaCacheIndexStore.touch = MediaCacheIndexEntriesMixin.__dict__["touch"]
MediaCacheIndexStore.remove = MediaCacheIndexCleanupMixin.__dict__["remove"]
MediaCacheIndexStore.remove_by_path = MediaCacheIndexCleanupMixin.__dict__[
    "remove_by_path"
]
MediaCacheIndexStore.is_index_file = MediaCacheIndexPathsMixin.__dict__["is_index_file"]
MediaCacheIndexStore.safe_remove = MediaCacheIndexCleanupMixin.__dict__["safe_remove"]


__all__ = [
    "MediaCacheIndexStore",
    "Path",
    "logger",
    "sqlite3",
    "threading",
    "time",
]
