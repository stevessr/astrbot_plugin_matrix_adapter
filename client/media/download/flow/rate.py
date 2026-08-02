"""Download semaphore and per-source rate-limit helpers."""

import asyncio
from contextlib import asynccontextmanager


class MediaDownloadFlowRateMixin:
    """Coordinate bounded concurrent downloads and source pacing."""

    def _get_media_download_semaphore(self, source_key: str) -> asyncio.Semaphore:
        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        limit = self._get_media_download_concurrency_limit()
        existing = self._media_download_semaphores.get(normalized_source)
        existing_limit = self._media_download_semaphore_limits.get(normalized_source)
        if existing is None or existing_limit != limit:
            existing = asyncio.Semaphore(limit)
            self._media_download_semaphores[normalized_source] = existing
            self._media_download_semaphore_limits[normalized_source] = limit
        return existing

    async def _apply_media_download_rate_limit(self, source_key: str) -> None:
        interval_seconds = self._get_media_download_min_interval_seconds()
        if interval_seconds <= 0:
            return

        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_rate_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        loop = asyncio.get_running_loop()
        async with lock:
            now = loop.time()
            next_allowed = self._media_download_next_allowed_at.get(
                normalized_source, now
            )
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = loop.time()
            self._media_download_next_allowed_at[normalized_source] = (
                now + interval_seconds
            )

    @asynccontextmanager
    async def _media_download_slot(self, source_key: str):
        semaphore = self._get_media_download_semaphore(source_key)
        await semaphore.acquire()
        try:
            await self._apply_media_download_rate_limit(source_key)
            yield
        finally:
            semaphore.release()
