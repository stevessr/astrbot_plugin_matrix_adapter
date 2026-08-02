"""Download circuit-breaker tracking and wait helpers."""

import asyncio
import time

from astrbot.api import logger


class MediaDownloadFlowBreakerMixin:
    """Track transient failures and temporarily open the breaker."""

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
