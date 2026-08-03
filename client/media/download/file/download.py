"""Full-size Matrix media download operation."""

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import aiohttp

from astrbot.api import logger

from ....path_utils import quote_path_segment


class MediaDownloadFileOperationMixin:
    """Download full-size media with retry and thumbnail fallback support."""

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
