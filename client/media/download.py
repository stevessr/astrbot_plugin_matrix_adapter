"""
Matrix HTTP Client - Media Download Mixin
Provides file download methods
"""

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import aiohttp

from astrbot.api import logger

from ...plugin_config import get_plugin_config
from ..path_utils import quote_path_segment


class MediaDownloadMixin:
    """Media download methods for Matrix client"""

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

    @staticmethod
    def _get_content_length(response: aiohttp.ClientResponse) -> int | None:
        header = response.headers.get("Content-Length")
        if header is None:
            return None
        try:
            parsed = int(header)
        except Exception:
            return None
        if parsed < 0:
            return None
        return parsed

    async def _read_response_with_memory_limit(
        self,
        response: aiohttp.ClientResponse,
        *,
        max_in_memory_bytes: int,
        resource_hint: str,
    ) -> bytes:
        if max_in_memory_bytes <= 0:
            return await response.read()

        content_length = self._get_content_length(response)
        if content_length is not None and content_length > max_in_memory_bytes:
            raise ValueError(
                "Matrix media download exceeds in-memory limit before reading "
                f"(content_length={content_length}, limit={max_in_memory_bytes}, "
                f"resource={resource_hint})"
            )

        buffer = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            if not chunk:
                continue
            buffer.extend(chunk)
            if len(buffer) > max_in_memory_bytes:
                raise ValueError(
                    "Matrix media download exceeds in-memory limit while reading "
                    f"(read={len(buffer)}, limit={max_in_memory_bytes}, "
                    f"resource={resource_hint})"
                )

        return bytes(buffer)

    async def _save_response_to_path(
        self, response: aiohttp.ClientResponse, output_path: Path
    ) -> None:
        temp_path = output_path.with_name(f".{output_path.name}.{time.time_ns()}.tmp")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with temp_path.open("wb") as f:
                async for chunk in response.content.iter_chunked(64 * 1024):
                    if chunk:
                        f.write(chunk)
            temp_path.replace(output_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    async def download_file(
        self,
        mxc_url: str,
        *,
        allow_thumbnail_fallback: bool = False,
        output_path: str | Path | None = None,
    ) -> bytes | None:
        """
        Download a file from the Matrix media repository
        按照 Matrix spec 正确实现媒体下载

        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid

        Args:
            mxc_url: MXC URL (mxc://server/media_id)
            allow_thumbnail_fallback: Whether to fallback to thumbnail on failure
            output_path: Optional local path to stream the response to

        Returns:
            File data as bytes, or None when output_path is provided
        """
        await self._ensure_session()
        resolved_output_path = Path(output_path) if output_path is not None else None

        server_name, media_id = self._parse_mxc_server_media_id(mxc_url)
        server_path = quote_path_segment(server_name)
        media_path = quote_path_segment(media_id)
        source_key = self._normalize_media_source_key(server_name)
        max_in_memory_bytes = self._get_media_download_max_in_memory_bytes()

        proxy_endpoints = [
            f"/_matrix/client/v1/media/download/{server_path}/{media_path}",
        ]
        direct_endpoints: list[str] = []
        public_endpoints: list[str] = []

        all_endpoints = (
            [(url, True, "proxy") for url in proxy_endpoints]
            + [(url, False, "direct") for url in direct_endpoints]
            + [(url, False, "public") for url in public_endpoints]
        )

        last_error = None
        last_status = None

        for endpoint_info in all_endpoints:
            endpoint, use_auth, strategy = endpoint_info
            if use_auth:
                url = f"{self.homeserver}{endpoint}"
            else:
                url = endpoint

            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if use_auth and self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            auth_status = (
                "with auth" if use_auth and self.access_token else "without auth"
            )
            logger.debug(
                f"Attempting media download from {url} {auth_status} (strategy: {strategy})"
            )

            attempt = 0
            while True:
                try:
                    await self._wait_media_download_breaker(source_key)
                    async with self._media_download_slot(source_key):
                        async with self.session.get(
                            url, headers=headers, allow_redirects=True
                        ) as response:
                            last_status = response.status
                            if response.status == 200:
                                await self._record_media_download_success(source_key)
                                logger.debug(
                                    f"Successfully downloaded media from {url}"
                                )
                                if resolved_output_path is not None:
                                    await self._save_response_to_path(
                                        response, resolved_output_path
                                    )
                                    return None
                                return await self._read_response_with_memory_limit(
                                    response,
                                    max_in_memory_bytes=max_in_memory_bytes,
                                    resource_hint=mxc_url,
                                )

                            retry_after_seconds = None
                            if response.status == 429:
                                retry_payload: dict[str, Any] = {}
                                try:
                                    parsed = await response.json(content_type=None)
                                    if isinstance(parsed, dict):
                                        retry_payload = parsed
                                except Exception:
                                    retry_payload = {}
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, retry_payload
                                )
                            elif response.status >= 500:
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, None
                                )

                            if (
                                self._should_retry_http_status(response.status)
                                and attempt < self._MEDIA_HTTP_MAX_RETRIES
                            ):
                                delay = self._compute_retry_delay(
                                    attempt, retry_after_seconds
                                )
                                attempt += 1
                                logger.debug(
                                    "Matrix media download failed with status "
                                    f"{response.status}, retrying in {delay:.2f}s "
                                    f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                )
                                await asyncio.sleep(delay)
                                continue

                            if self._is_media_download_breaker_failure_status(
                                response.status
                            ):
                                await self._record_media_download_failure(
                                    source_key, response.status
                                )
                            if response.status == 404:
                                last_error = f"Media not found: {response.status}"
                            elif response.status == 403:
                                last_error = f"Access denied: {response.status}"
                                logger.debug(
                                    f"Got 403 on {url} (auth problem or private media)"
                                )
                            else:
                                last_error = f"HTTP {response.status}"
                            break

                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.debug(
                            "Matrix media download network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    await self._record_media_download_failure(source_key, None)
                    last_error = str(e)
                    logger.debug(f"Network error downloading from {url}: {e}")
                    break
                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"Exception downloading from {url}: {e}")
                    break

        if allow_thumbnail_fallback and last_status in [403, 404]:
            logger.debug("Trying thumbnail endpoints as fallback...")
            thumbnail_query = urlencode({"width": 800, "height": 600})
            thumbnail_endpoints = [
                f"/_matrix/client/v1/media/thumbnail/{server_path}/{media_path}?{thumbnail_query}",
            ]

            for endpoint in thumbnail_endpoints:
                url = f"{self.homeserver}{endpoint}"
                headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
                if self.access_token:
                    headers["Authorization"] = f"Bearer {self.access_token}"

                attempt = 0
                while True:
                    try:
                        await self._wait_media_download_breaker(source_key)
                        async with self._media_download_slot(source_key):
                            async with self.session.get(
                                url, headers=headers, allow_redirects=True
                            ) as response:
                                if response.status == 200:
                                    await self._record_media_download_success(
                                        source_key
                                    )
                                    logger.debug(
                                        "Downloaded thumbnail instead of full media"
                                    )
                                    if resolved_output_path is not None:
                                        await self._save_response_to_path(
                                            response, resolved_output_path
                                        )
                                        return None
                                    return await self._read_response_with_memory_limit(
                                        response,
                                        max_in_memory_bytes=max_in_memory_bytes,
                                        resource_hint=mxc_url,
                                    )

                                if (
                                    self._should_retry_http_status(response.status)
                                    and attempt < self._MEDIA_HTTP_MAX_RETRIES
                                ):
                                    retry_after_seconds = (
                                        self._extract_retry_after_seconds(
                                            response.headers, None
                                        )
                                    )
                                    delay = self._compute_retry_delay(
                                        attempt, retry_after_seconds
                                    )
                                    attempt += 1
                                    await asyncio.sleep(delay)
                                    continue
                                if self._is_media_download_breaker_failure_status(
                                    response.status
                                ):
                                    await self._record_media_download_failure(
                                        source_key, response.status
                                    )
                                break
                    except aiohttp.ClientError:
                        if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                            delay = self._compute_retry_delay(attempt)
                            attempt += 1
                            await asyncio.sleep(delay)
                            continue
                        await self._record_media_download_failure(source_key, None)
                        break
                    except Exception:
                        break

        error_msg = f"Matrix media download error: {last_error} (last status: {last_status}) for {mxc_url}"
        logger.error(error_msg)
        raise Exception(error_msg)

    async def get_thumbnail(
        self,
        mxc_url: str,
        width: int,
        height: int,
        method: str | None = None,
        animated: bool | None = None,
    ) -> bytes:
        """
        Get a thumbnail for media

        Args:
            mxc_url: MXC URL (mxc://server/media_id)
            width: Thumbnail width
            height: Thumbnail height
            method: Optional method (crop, scale)
            animated: Optional animated flag

        Returns:
            Thumbnail bytes
        """
        await self._ensure_session()

        server_name, media_id = self._parse_mxc_server_media_id(mxc_url)
        server_path = quote_path_segment(server_name)
        media_path = quote_path_segment(media_id)
        source_key = self._normalize_media_source_key(server_name)
        max_in_memory_bytes = self._get_media_download_max_in_memory_bytes()
        query_params: dict[str, Any] = {"width": width, "height": height}
        if method:
            query_params["method"] = method
        if animated is not None:
            query_params["animated"] = "true" if animated else "false"
        query = urlencode(query_params)

        endpoints = [
            f"/_matrix/client/v1/media/thumbnail/{server_path}/{media_path}?{query}",
        ]

        last_error = None
        last_status = None

        for endpoint in endpoints:
            url = f"{self.homeserver}{endpoint}"
            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            attempt = 0
            while True:
                try:
                    await self._wait_media_download_breaker(source_key)
                    async with self._media_download_slot(source_key):
                        async with self.session.get(
                            url, headers=headers, allow_redirects=True
                        ) as response:
                            last_status = response.status
                            if response.status == 200:
                                await self._record_media_download_success(source_key)
                                return await self._read_response_with_memory_limit(
                                    response,
                                    max_in_memory_bytes=max_in_memory_bytes,
                                    resource_hint=mxc_url,
                                )

                            retry_after_seconds = None
                            if response.status == 429:
                                retry_payload: dict[str, Any] = {}
                                try:
                                    parsed = await response.json(content_type=None)
                                    if isinstance(parsed, dict):
                                        retry_payload = parsed
                                except Exception:
                                    retry_payload = {}
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, retry_payload
                                )
                            elif response.status >= 500:
                                retry_after_seconds = self._extract_retry_after_seconds(
                                    response.headers, None
                                )

                            if (
                                self._should_retry_http_status(response.status)
                                and attempt < self._MEDIA_HTTP_MAX_RETRIES
                            ):
                                delay = self._compute_retry_delay(
                                    attempt, retry_after_seconds
                                )
                                attempt += 1
                                logger.debug(
                                    "Matrix thumbnail request failed with status "
                                    f"{response.status}, retrying in {delay:.2f}s "
                                    f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                                )
                                await asyncio.sleep(delay)
                                continue

                            if self._is_media_download_breaker_failure_status(
                                response.status
                            ):
                                await self._record_media_download_failure(
                                    source_key, response.status
                                )
                            last_error = f"HTTP {response.status}"
                            break
                except aiohttp.ClientError as e:
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.debug(
                            "Matrix thumbnail network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    await self._record_media_download_failure(source_key, None)
                    last_error = str(e)
                    break
                except Exception as e:
                    last_error = str(e)
                    break

        error_msg = (
            f"Matrix thumbnail error: {last_error} (last status: {last_status}) "
            f"for {mxc_url}"
        )
        logger.error(error_msg)
        raise Exception(error_msg)
