"""Single-endpoint media download attempt loop with retries."""

import asyncio
from pathlib import Path

import aiohttp

from astrbot.api import logger

from .error import MediaDownloadAttemptErrorMixin
from .success import MediaDownloadAttemptSuccessMixin
from .throttle import MediaDownloadAttemptThrottleMixin


class MediaDownloadAttemptOrchestratorMixin(
    MediaDownloadAttemptSuccessMixin,
    MediaDownloadAttemptThrottleMixin,
    MediaDownloadAttemptErrorMixin,
):
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
                            return await self._complete_successful_download(
                                url,
                                response,
                                source_key=source_key,
                                resolved_output_path=resolved_output_path,
                                max_in_memory_bytes=max_in_memory_bytes,
                                mxc_url=mxc_url,
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
                                "Matrix media download failed with status "
                                f"{response.status}, retrying in {delay:.2f}s "
                                f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                            )
                            await asyncio.sleep(delay)
                            continue

                        last_error = await self._finalize_http_error(
                            url, response, source_key
                        )
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


__all__ = [
    "MediaDownloadAttemptErrorMixin",
    "MediaDownloadAttemptOrchestratorMixin",
    "MediaDownloadAttemptSuccessMixin",
    "MediaDownloadAttemptThrottleMixin",
]
