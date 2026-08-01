"""Matrix URL preview helpers."""

from typing import Any


class MediaPreviewMixin:
    """Request URL preview metadata from the media repository."""

    async def get_url_preview(
        self, url: str, timestamp_ms: int | None = None
    ) -> dict[str, Any]:
        """
        Get URL preview metadata

        Args:
            url: URL to preview
            timestamp_ms: Optional timestamp in milliseconds

        Returns:
            Preview response
        """
        params: dict[str, Any] = {"url": url}
        if timestamp_ms is not None:
            params["ts"] = timestamp_ms

        endpoints = ["/_matrix/client/v1/media/preview_url"]

        last_error: Exception | None = None
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint, params=params)
            except Exception as e:
                last_error = e
                continue

        raise Exception(f"Matrix URL preview error: {last_error}")
