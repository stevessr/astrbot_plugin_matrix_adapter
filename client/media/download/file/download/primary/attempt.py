"""Single-endpoint media download attempt loop with retries."""

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger


class MediaDownloadAttemptMixin:
    """Retry-and-breaker aware download attempts against one endpoint."""

    async def _download_from_endpoint(
        self,
        url: str,
        headers: dict,
        *,
        source_key: str,
        mxc_url: str,
        resolved_output_path: Path | None,
        max_in_memory_bytes: int,
    ) -> tuple[str | None, int | None, bytes | None]:
        """Download from one endpoint, returning (error, status, payload)."""
        last_error = None
        last_status = None

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
                            logger.debug(f"Successfully downloaded media from {url}")
                            if resolved_output_path is not None:
                                await self._save_response_to_path(
                                    response, resolved_output_path
                                )
                                return None, 200, None
                            payload = await self._read_response_with_memory_limit(
                                response,
                                max_in_memory_bytes=max_in_memory_bytes,
                                resource_hint=mxc_url,
                            )
                            return None, 200, payload

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
                        return last_error, last_status, None

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
                return last_error, last_status, None
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Exception downloading from {url}: {e}")
                return last_error, last_status, None
