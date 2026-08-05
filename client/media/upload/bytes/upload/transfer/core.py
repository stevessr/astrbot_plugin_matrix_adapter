"""Byte-buffer Matrix media upload transfer with retry and async upload."""

import asyncio
from typing import Any

import aiohttp

from astrbot.api import logger

from .......constants import HTTP_ERROR_STATUS_400
from .request import MediaUploadBytesRequestMixin
from .result import MediaUploadBytesResultMixin


class MediaUploadBytesTransferCoreMixin(
    MediaUploadBytesRequestMixin,
    MediaUploadBytesResultMixin,
):
    """Perform the HTTP media upload, with endpoint fallback and retries."""

    async def _perform_media_upload(
        self,
        *,
        cache_key: str,
        safe_content_type: str,
        filename: str,
        data: bytes,
    ) -> dict[str, Any]:
        headers = {
            "Content-Type": safe_content_type,
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        params = {"filename": filename}
        endpoints = self._get_media_upload_endpoints()
        last_error: Exception | None = None

        for endpoint_index, endpoint in enumerate(endpoints):
            url = f"{self.homeserver}{endpoint}"
            attempt = 0

            while True:
                try:
                    (
                        response_status,
                        response_data,
                        response_headers,
                    ) = await self._post_media_upload_once(
                        url=url,
                        data=data,
                        headers=headers,
                        params=params,
                    )

                    if response_status >= HTTP_ERROR_STATUS_400:
                        if self._should_try_next_media_upload_endpoint(
                            response_status,
                            endpoint_index,
                            len(endpoints),
                        ):
                            logger.warning(
                                "Matrix media upload endpoint returned 404, "
                                "trying fallback endpoint: %s",
                                endpoint,
                            )
                            break

                        retry_after_seconds = self._extract_retry_after_seconds(
                            response_headers, response_data
                        )
                        if (
                            self._should_retry_http_status(response_status)
                            and attempt < self._MEDIA_HTTP_MAX_RETRIES
                        ):
                            delay = self._compute_retry_delay(
                                attempt, retry_after_seconds
                            )
                            attempt += 1
                            logger.warning(
                                "Matrix media upload failed with status "
                                f"{response_status}, retrying in {delay:.2f}s "
                                f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                            )
                            await asyncio.sleep(delay)
                            continue

                        error_code = response_data.get("errcode", "UNKNOWN")
                        error_msg = response_data.get("error", "Unknown error")
                        last_error = Exception(
                            f"Matrix media upload error: {error_code} - {error_msg}"
                        )
                        raise last_error

                    return await self._consume_upload_result(
                        response_data=response_data,
                        cache_key=cache_key,
                    )

                except aiohttp.ClientError as e:
                    last_error = e
                    if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                        delay = self._compute_retry_delay(attempt)
                        attempt += 1
                        logger.warning(
                            "Matrix media upload network error, retrying in "
                            f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {e}"
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise

        if last_error is not None:
            raise last_error
        raise Exception("Matrix media upload error: no upload endpoint available")
