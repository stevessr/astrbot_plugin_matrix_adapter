"""Matrix media upload endpoint transfer and retry logic."""

import asyncio
from pathlib import Path
from typing import Any

from astrbot.api import logger

from ..request import MediaUploadTransferRequestMixin
from ..result import MediaUploadTransferResultMixin
from .attempt import MediaUploadTransferAttemptMixin
from .retry import MediaUploadTransferRetryMixin
from .setup import MediaUploadTransferSetupMixin


class MediaUploadTransferOrchestratorMixin(
    MediaUploadTransferRequestMixin,
    MediaUploadTransferResultMixin,
    MediaUploadTransferRetryMixin,
    MediaUploadTransferAttemptMixin,
    MediaUploadTransferSetupMixin,
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
        headers = self._build_upload_request_headers(safe_content_type)
        params = self._build_upload_request_params(upload_filename)
        endpoints = self._get_media_upload_endpoints()
        last_error: Exception | None = None

        for endpoint_index, endpoint in enumerate(endpoints):
            url = f"{self.homeserver}{endpoint}"
            attempt = 0

            while True:
                decision = await self._run_single_upload_attempt(
                    url=url,
                    headers=headers,
                    params=params,
                    path=path,
                    path_cache_key=path_cache_key,
                    safe_content_type=safe_content_type,
                )
                decision_kind = decision[0]

                if decision_kind == "success":
                    return decision[1]

                if decision_kind == "status":
                    status, response_data, response_headers = decision[1:]
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

                last_error = decision[1]
                if attempt < self._MEDIA_HTTP_MAX_RETRIES:
                    delay = self._compute_retry_delay(attempt)
                    attempt += 1
                    logger.warning(
                        "Matrix media upload network error, retrying in "
                        f"{delay:.2f}s ({attempt}/{self._MEDIA_HTTP_MAX_RETRIES}): {last_error}"
                    )
                    await asyncio.sleep(delay)
                    continue
                raise last_error

        if last_error is not None:
            raise last_error
        raise Exception("Matrix media upload error: no upload endpoint available")


__all__ = [
    "MediaUploadTransferAttemptMixin",
    "MediaUploadTransferOrchestratorMixin",
    "MediaUploadTransferRetryMixin",
    "MediaUploadTransferSetupMixin",
]
