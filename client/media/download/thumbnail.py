"""Matrix media thumbnail download operation."""

import asyncio
from typing import Any
from urllib.parse import urlencode

import aiohttp

from astrbot.api import logger

from ...path_utils import quote_path_segment


class MediaDownloadThumbnailMixin:
    """Download thumbnails with the shared flow-control primitives."""

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
