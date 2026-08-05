"""Thumbnail fallback endpoint construction."""

from urllib.parse import urlencode


class MediaDownloadThumbnailEndpointMixin:
    """Build thumbnail fallback URLs and request headers."""

    def _build_thumbnail_endpoint_url(
        self,
        server_path: str,
        media_path: str,
    ) -> str:
        thumbnail_query = urlencode({"width": 800, "height": 600})
        return (
            f"/_matrix/client/v1/media/thumbnail/{server_path}/{media_path}"
            f"?{thumbnail_query}"
        )

    def _build_thumbnail_request_headers(self) -> dict[str, str]:
        headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers


__all__ = ["MediaDownloadThumbnailEndpointMixin"]
