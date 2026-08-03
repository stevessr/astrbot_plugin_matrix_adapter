"""Composable Matrix media upload cache operations."""

import asyncio  # noqa: F401
import hashlib  # noqa: F401
import time  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any  # noqa: F401

from astrbot.api import logger  # noqa: F401

from .keys import MediaUploadCacheKeysMixin
from .state import MediaUploadCacheStateMixin


class MediaUploadCacheMixin(
    MediaUploadCacheStateMixin,
    MediaUploadCacheKeysMixin,
):
    """Deduplicate and cache recent media upload results."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaUploadCacheMixin._ensure_media_upload_cache = MediaUploadCacheStateMixin.__dict__[
    "_ensure_media_upload_cache"
]
MediaUploadCacheMixin._build_media_upload_cache_key = (
    MediaUploadCacheKeysMixin.__dict__["_build_media_upload_cache_key"]
)
MediaUploadCacheMixin._build_media_upload_cache_key_from_digest = (
    MediaUploadCacheKeysMixin.__dict__["_build_media_upload_cache_key_from_digest"]
)
MediaUploadCacheMixin._build_media_upload_cache_key_from_file_state = (
    MediaUploadCacheKeysMixin.__dict__["_build_media_upload_cache_key_from_file_state"]
)
MediaUploadCacheMixin._prune_media_upload_cache = MediaUploadCacheStateMixin.__dict__[
    "_prune_media_upload_cache"
]
MediaUploadCacheMixin._get_cached_upload_result = MediaUploadCacheStateMixin.__dict__[
    "_get_cached_upload_result"
]
MediaUploadCacheMixin._save_upload_cache_result = MediaUploadCacheStateMixin.__dict__[
    "_save_upload_cache_result"
]


__all__ = [
    "Any",
    "MediaUploadCacheMixin",
    "Path",
    "asyncio",
    "hashlib",
    "logger",
    "time",
]
