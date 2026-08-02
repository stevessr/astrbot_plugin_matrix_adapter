"""Download flow-control state initialization."""

import asyncio


class MediaDownloadFlowStateMixin:
    """Initialize per-source semaphores, locks, and breaker state."""

    def _ensure_media_download_flow_control(self) -> None:
        if not hasattr(self, "_media_download_semaphores"):
            self._media_download_semaphores: dict[str, asyncio.Semaphore] = {}
        if not hasattr(self, "_media_download_semaphore_limits"):
            self._media_download_semaphore_limits: dict[str, int] = {}
        if not hasattr(self, "_media_download_rate_locks"):
            self._media_download_rate_locks: dict[str, asyncio.Lock] = {}
        if not hasattr(self, "_media_download_next_allowed_at"):
            self._media_download_next_allowed_at: dict[str, float] = {}
        if not hasattr(self, "_media_download_breaker_failures"):
            self._media_download_breaker_failures: dict[str, int] = {}
        if not hasattr(self, "_media_download_breaker_open_until"):
            self._media_download_breaker_open_until: dict[str, float] = {}
        if not hasattr(self, "_media_download_breaker_locks"):
            self._media_download_breaker_locks: dict[str, asyncio.Lock] = {}
