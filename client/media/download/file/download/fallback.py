"""Thumbnail fallback for full-size Matrix media downloads."""

import asyncio
from pathlib import Path
from urllib.parse import urlencode

import aiohttp

from astrbot.api import logger


class MediaDownloadThumbnailFallbackMixin:
    """Retry media downloads through thumbnail endpoints."""

    async def _download_thumbnail_fallback(
        self,
        *,
        allow_thumbnail_fallback: bool,
        last_status: int | None,
        server_path: str,
        media_path: str,
        source_key: str,
        resolved_output_path: Path | None,
        max_in_memory_bytes: int | None,
        mxc_url: str,
    ) -> tuple[bool, bytes | None]:
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
                                        return True, None
                                    return (
                                        True,
                                        await self._read_response_with_memory_limit(
                                            response,
                                            max_in_memory_bytes=max_in_memory_bytes,
                                            resource_hint=mxc_url,
                                        ),
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
        return False, None
