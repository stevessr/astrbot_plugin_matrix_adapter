"""Matrix media thumbnail HTTP transfer with retries and flow control."""

import asyncio
from typing import Any

import aiohttp

from astrbot.api import logger


class MediaDownloadThumbnailTransferMixin:
    """Perform the thumbnail download with retry and flow-control primitives."""

    async def _perform_thumbnail_download(
        self,
        *,
        url: str,
        source_key: str,
        max_in_memory_bytes: int,
        mxc_url: str,
    ) -> tuple[bytes | None, str | None, int | None]:
        """Return ``(result_bytes, last_error, last_status)`` on failure."""
        headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        last_error: str | None = None
        last_status: int | None = None
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
                            return (
                                await self._read_response_with_memory_limit(
                                    response,
                                    max_in_memory_bytes=max_in_memory_bytes,
                                    resource_hint=mxc_url,
                                ),
                                None,
                                None,
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

        return None, last_error, last_status
