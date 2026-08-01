"""Concurrency, rate-limit, and circuit-breaker controls for media downloads."""

import asyncio
import time
from contextlib import asynccontextmanager

from astrbot.api import logger

from ....config.plugin import get_plugin_config


class MediaDownloadFlowControlMixin:
    """Shared flow-control primitives for media download operations."""

    _MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT = 4

    _MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT = 32 * 1024 * 1024

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

    @staticmethod
    def _normalize_media_source_key(source_key: str | None) -> str:
        if isinstance(source_key, str):
            normalized = source_key.strip().lower()
            if normalized:
                return normalized
        return "__homeserver__"

    def _get_media_download_concurrency_limit(self) -> int:
        default_limit = self._MEDIA_DOWNLOAD_CONCURRENCY_DEFAULT
        try:
            configured_limit = int(get_plugin_config().media_download_concurrency)
        except Exception:
            return default_limit
        if configured_limit <= 0:
            return default_limit
        return min(configured_limit, 64)

    def _get_media_download_max_in_memory_bytes(self) -> int:
        default_limit = self._MEDIA_DOWNLOAD_MAX_IN_MEMORY_BYTES_DEFAULT
        try:
            configured_limit = int(
                get_plugin_config().media_download_max_in_memory_bytes
            )
        except Exception:
            return default_limit
        if configured_limit <= 0:
            return 0
        return min(configured_limit, 1024 * 1024 * 1024)

    def _get_media_download_min_interval_seconds(self) -> float:
        try:
            interval_ms = int(get_plugin_config().media_download_min_interval_ms)
        except Exception:
            return 0.0
        if interval_ms <= 0:
            return 0.0
        return interval_ms / 1000.0

    def _get_media_download_breaker_fail_threshold(self) -> int:
        try:
            threshold = int(get_plugin_config().media_download_breaker_fail_threshold)
        except Exception:
            return 6
        return max(0, threshold)

    def _get_media_download_breaker_base_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(get_plugin_config().media_download_breaker_cooldown_ms)
        except Exception:
            return 5.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _get_media_download_breaker_max_cooldown_seconds(self) -> float:
        try:
            cooldown_ms = int(
                get_plugin_config().media_download_breaker_max_cooldown_ms
            )
        except Exception:
            return 120.0
        if cooldown_ms <= 0:
            return 0.0
        return cooldown_ms / 1000.0

    def _is_media_download_breaker_enabled(self) -> bool:
        if self._get_media_download_breaker_fail_threshold() <= 0:
            return False
        return self._get_media_download_breaker_base_cooldown_seconds() > 0

    @staticmethod
    def _is_media_download_breaker_failure_status(status: int) -> bool:
        return status == 429 or status >= 500

    async def _wait_media_download_breaker(self, source_key: str) -> None:
        if not self._is_media_download_breaker_enabled():
            return

        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_breaker_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        sleep_for = 0.0

        async with lock:
            open_until = self._media_download_breaker_open_until.get(
                normalized_source, 0.0
            )
            now = time.monotonic()
            if open_until > now:
                sleep_for = open_until - now

        if sleep_for > 0:
            logger.debug(
                "Matrix media download breaker open for "
                f"{normalized_source}, waiting {sleep_for:.2f}s"
            )
            await asyncio.sleep(sleep_for)

    async def _record_media_download_success(self, source_key: str) -> None:
        self._ensure_media_download_flow_control()
        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_breaker_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        async with lock:
            if self._media_download_breaker_failures.get(normalized_source, 0) > 0:
                self._media_download_breaker_failures[normalized_source] = 0
                self._media_download_breaker_open_until[normalized_source] = 0.0

    async def _record_media_download_failure(
        self, source_key: str, status: int | None
    ) -> None:
        if not self._is_media_download_breaker_enabled():
            return
        self._ensure_media_download_flow_control()

        normalized_source = self._normalize_media_source_key(source_key)
        lock = self._media_download_breaker_locks.setdefault(
            normalized_source, asyncio.Lock()
        )
        async with lock:
            failure_count = (
                self._media_download_breaker_failures.get(normalized_source, 0) + 1
            )
            self._media_download_breaker_failures[normalized_source] = failure_count

            threshold = self._get_media_download_breaker_fail_threshold()
            if failure_count < threshold:
                return

            base_cooldown = self._get_media_download_breaker_base_cooldown_seconds()
            max_cooldown = self._get_media_download_breaker_max_cooldown_seconds()
            if max_cooldown <= 0:
                max_cooldown = base_cooldown
            if max_cooldown <= 0:
                return

            backoff_level = failure_count - threshold
            cooldown_seconds = min(base_cooldown * (2**backoff_level), max_cooldown)
            now = time.monotonic()
            new_open_until = now + cooldown_seconds
            current_open_until = self._media_download_breaker_open_until.get(
                normalized_source, 0.0
            )
            if new_open_until > current_open_until:
                self._media_download_breaker_open_until[normalized_source] = (
                    new_open_until
                )

            logger.debug(
                "Opened Matrix media download breaker for "
                f"{normalized_source}: failures={failure_count}, "
                f"status={status}, cooldown={cooldown_seconds:.2f}s"
            )

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
