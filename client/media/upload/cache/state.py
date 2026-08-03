"""Matrix media upload cache state operations."""

import asyncio
import time
from typing import Any

from astrbot.api import logger


class MediaUploadCacheStateMixin:
    """Initialize, prune, read, and save upload cache state."""

    def _ensure_media_upload_cache(self) -> None:
        if not hasattr(self, "_media_upload_cache"):
            self._media_upload_cache: dict[str, tuple[str, float]] = {}
        if not hasattr(self, "_media_upload_inflight"):
            self._media_upload_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}

    def _prune_media_upload_cache(self, now: float) -> None:
        expired_keys = [
            key
            for key, (_, ts) in self._media_upload_cache.items()
            if (now - ts) > self._MEDIA_UPLOAD_CACHE_TTL_SECONDS
        ]
        for key in expired_keys:
            self._media_upload_cache.pop(key, None)

        overflow = len(self._media_upload_cache) - self._MEDIA_UPLOAD_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return

        oldest_keys = sorted(
            self._media_upload_cache.items(),
            key=lambda item: item[1][1],
        )[:overflow]
        for key, _ in oldest_keys:
            self._media_upload_cache.pop(key, None)

    def _get_cached_upload_result(self, cache_key: str) -> dict[str, Any] | None:
        now = time.monotonic()
        cached = self._media_upload_cache.get(cache_key)
        if cached and (now - cached[1]) <= self._MEDIA_UPLOAD_CACHE_TTL_SECONDS:
            logger.debug(
                "Reusing recent Matrix media upload result from in-memory cache"
            )
            return {"content_uri": cached[0]}
        return None

    def _save_upload_cache_result(self, cache_key: str, content_uri: str) -> None:
        now_inner = time.monotonic()
        self._media_upload_cache[cache_key] = (content_uri, now_inner)
        self._prune_media_upload_cache(now_inner)
