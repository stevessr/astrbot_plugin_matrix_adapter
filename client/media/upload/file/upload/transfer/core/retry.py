"""Upload HTTP status decision for the endpoint retry loop."""

from typing import Any

from astrbot.api import logger


class MediaUploadTransferRetryMixin:
    """Decide the next action for an unsuccessful upload response."""

    def _decide_upload_status_action(
        self,
        status: int,
        endpoint: str,
        endpoint_index: int,
        endpoints: list,
        response_data: dict[str, Any],
        response_headers,
        attempt: int,
    ):
        if self._should_try_next_media_upload_endpoint(
            status,
            endpoint_index,
            len(endpoints),
        ):
            logger.warning(
                "Matrix media upload endpoint returned 404, "
                f"trying fallback endpoint: {endpoint}"
            )
            return ("switch", None)

        retry_after_seconds = self._extract_retry_after_seconds(
            response_headers, response_data
        )
        if (
            self._should_retry_http_status(status)
            and attempt < self._MEDIA_HTTP_MAX_RETRIES
        ):
            delay = self._compute_retry_delay(attempt, retry_after_seconds)
            return ("retry", delay)

        error_code = response_data.get("errcode", "UNKNOWN")
        error_msg = response_data.get("error", "Unknown error")
        last_error = Exception(f"Matrix media upload error: {error_code} - {error_msg}")
        return ("raise", last_error)


__all__ = ["MediaUploadTransferRetryMixin"]
