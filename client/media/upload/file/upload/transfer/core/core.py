"""Matrix media upload endpoint transfer and retry logic."""

import asyncio
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api import logger

from ........constants import HTTP_ERROR_STATUS_400
from ..request import MediaUploadTransferRequestMixin
from ..result import MediaUploadTransferResultMixin
from .retry import MediaUploadTransferRetryMixin


class MediaUploadTransferOrchestratorMixin(
    MediaUploadTransferRequestMixin,
    MediaUploadTransferResultMixin,
    MediaUploadTransferRetryMixin,
):
    """Upload a prepared file to Matrix endpoints."""

    async def _perform_upload_from_path(
        self,
        *,
        path: Path,
        safe_content_type: str,
        upload_filename: str,
        path_cache_key: str,
    ) -> dict[str, Any]:
        headers = {
            "Content-Type": safe_content_type,
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        params = {"filename": upload_filename}
        endpoints = self._get_media_upload_endpoints()
        last_error: Exception | None = None

        for endpoint_index, endpoint in enumerate(endpoints):
            url = f"{self.homeserver}{endpoint}"
            attempt = 0

            while True:
                file_handle = None
                try:
                    file_handle = await asyncio.to_thread(path.open, "rb")
                    hashing_reader = self._HashingFileReader(file_handle)
                    (
                        status,
                        response_data,
                        response_headers,
                    ) = await self._post_upload_request_once(
                        url,
                        headers,
                        params,
                        hashing_reader,
                    )

                    if status >= HTTP_ERROR_STATUS_400:
                        action, action_arg = self._decide_upload_status_action(
                            status,
                            endpoint,
                            endpoint_index,
                            endpoints,
                            response_data,
                            response_headers,
                            attempt,
                        )
                        if action == "switch":
                            break
                        if action == "retry":
                            delay = action_arg
                            attempt += 1
                            logger.warning(
                                "Matrix media upload failed with status "
                                f"{status}, retrying in {delay:.2f}s "
                                f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                            )
                            await asyncio.sleep(delay)
                            continue
                        last_error = action_arg
                        raise last_error

                    return await self._consume_upload_result(
                        response_data,
                        hashing_reader,
                        path_cache_key,
                        safe_content_type,
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
                finally:
                    if file_handle is not None:
                        await asyncio.to_thread(file_handle.close)

        if last_error is not None:
            raise last_error
        raise Exception("Matrix media upload error: no upload endpoint available")


__all__ = [
    "MediaUploadTransferOrchestratorMixin",
    "MediaUploadTransferRetryMixin",
]
