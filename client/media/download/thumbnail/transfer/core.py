"""Matrix media thumbnail HTTP transfer with retries and flow control."""

import asyncio

import aiohttp

from astrbot.api import logger

from .success import MediaDownloadThumbnailSuccessMixin
from .throttle import MediaDownloadThumbnailThrottleMixin


class MediaDownloadThumbnailOrchestratorMixin(
    MediaDownloadThumbnailSuccessMixin,
    MediaDownloadThumbnailThrottleMixin,
):
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
                            return await self._complete_thumbnail_success(
                                response,
                                source_key,
                                max_in_memory_bytes,
                                mxc_url,
                            )

                        retry_after_seconds = await self._compute_response_retry_after(
                            response
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


__all__ = [
    "MediaDownloadThumbnailOrchestratorMixin",
    "MediaDownloadThumbnailSuccessMixin",
    "MediaDownloadThumbnailThrottleMixin",
]
