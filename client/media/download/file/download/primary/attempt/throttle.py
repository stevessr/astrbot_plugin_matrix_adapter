"""HTTP retry-after computation for media downloads."""

from typing import Any


class MediaDownloadAttemptThrottleMixin:
    """Derive a retry delay hint from an unsuccessful response."""

    async def _compute_response_retry_after(self, response):
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
        return retry_after_seconds


__all__ = ["MediaDownloadAttemptThrottleMixin"]
