"""Matrix media upload retry delay calculations."""

from typing import Any

import aiohttp


class MediaUploadRetryDelayMixin:
    """Calculate retry-after and exponential backoff delays."""

    @staticmethod
    def _coerce_retry_after_seconds(value: Any) -> float | None:
        if value is None:
            return None
        try:
            retry_after = float(value)
        except (TypeError, ValueError):
            return None
        if retry_after <= 0:
            return None
        return retry_after

    def _extract_retry_after_seconds(
        self,
        response_headers: "aiohttp.typedefs.LooseHeaders",
        response_data: dict[str, Any] | None = None,
    ) -> float | None:
        retry_after = self._coerce_retry_after_seconds(
            (response_data or {}).get("retry_after_ms")
        )
        if retry_after is not None:
            return min(retry_after / 1000.0, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

        header_value = None
        try:
            header_value = response_headers.get("Retry-After")
        except Exception:
            header_value = None
        retry_after_header = self._coerce_retry_after_seconds(header_value)
        if retry_after_header is None:
            return None
        return min(retry_after_header, self._MEDIA_RETRY_MAX_DELAY_SECONDS)

    def _compute_retry_delay(
        self, attempt: int, retry_after_seconds: float | None = None
    ) -> float:
        if retry_after_seconds is not None:
            return max(0.1, retry_after_seconds)
        return min(
            self._MEDIA_RETRY_BASE_DELAY_SECONDS * (2**attempt),
            self._MEDIA_RETRY_MAX_DELAY_SECONDS,
        )
