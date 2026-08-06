"""Upload request header and parameter building."""

from typing import Any


class MediaUploadTransferSetupMixin:
    """Build upload request headers and parameters."""

    def _build_upload_request_headers(self, safe_content_type: str) -> dict[str, str]:
        """Build the authenticated upload headers."""
        headers = {
            "Content-Type": safe_content_type,
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        return headers

    def _build_upload_request_params(self, upload_filename: str) -> dict[str, Any]:
        """Build the upload query parameters."""
        params = {"filename": upload_filename}
        return params


__all__ = ["MediaUploadTransferSetupMixin"]
