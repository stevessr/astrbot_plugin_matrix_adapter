"""Byte-upload status action decisions."""

from astrbot.api import logger

from ........constants import HTTP_ERROR_STATUS_400


class MediaUploadBytesTransferRetryMixin:
    """Decide the next action for an upload response status."""

    def _decide_media_upload_status_action(
        self,
        response_status: int,
        response_data: dict,
        response_headers,
        endpoint_index: int,
        endpoint: str,
        endpoints,
        attempt: int,
    ):
        """Return ``("next", None)``, ``("retry", delay)``, ``("raise", exc)``, or ``("success", None)``."""
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
                return ("next", None)

            retry_after_seconds = self._extract_retry_after_seconds(
                response_headers, response_data
            )
            if (
                self._should_retry_http_status(response_status)
                and attempt < self._MEDIA_HTTP_MAX_RETRIES
            ):
                delay = self._compute_retry_delay(attempt, retry_after_seconds)
                return ("retry", delay)

            error_code = response_data.get("errcode", "UNKNOWN")
            error_msg = response_data.get("error", "Unknown error")
            last_error = Exception(
                f"Matrix media upload error: {error_code} - {error_msg}"
            )
            return ("raise", last_error)
        return ("success", None)


__all__ = ["MediaUploadBytesTransferRetryMixin"]
