"""Byte-buffer media upload orchestration."""

import asyncio
from typing import Any

import aiohttp

from astrbot.api import logger


class MediaUploadBytesTransferOrchestratorMixin:
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

                    action = self._decide_media_upload_status_action(
                        response_status,
                        response_data,
                        response_headers,
                        endpoint_index,
                        endpoint,
                        endpoints,
                        attempt,
                    )
                    action_kind, action_value = action

                    if action_kind == "next":
                        break

                    if action_kind == "retry":
                        attempt += 1
                        logger.warning(
                            "Matrix media upload failed with status "
                            f"{response_status}, retrying in {action_value:.2f}s "
                            f"({attempt}/{self._MEDIA_HTTP_MAX_RETRIES})"
                        )
                        await asyncio.sleep(action_value)
                        continue

                    if action_kind == "raise":
                        raise action_value

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


__all__ = ["MediaUploadBytesTransferOrchestratorMixin"]
