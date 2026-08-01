"""Matrix media upload endpoint and async-status helpers."""

import asyncio
import time
from typing import Any

from ...base import MatrixAPIError
from ...path_utils import quote_path_segment


class MediaUploadEndpointMixin:
    """Select upload endpoints and poll asynchronous uploads."""

    @staticmethod
    def _get_media_upload_endpoints() -> tuple[str, ...]:
        """Return preferred media upload endpoints in compatibility order."""
        return (
            "/_matrix/client/v1/media/upload",
            "/_matrix/media/v3/upload",
        )

    @staticmethod
    def _get_media_upload_status_endpoint(upload_id: str) -> str:
        """Return the upload status endpoint for async upload (MSC2246)."""
        return f"/_matrix/client/v1/media/upload/{quote_path_segment(upload_id)}"

    async def _poll_upload_status(self, upload_id: str) -> dict[str, Any]:
        """
        Poll the upload status endpoint until the async upload completes
        (MSC2246 asynchronous media uploads).

        Returns the final response dict containing ``content_uri``.
        """
        endpoint = self._get_media_upload_status_endpoint(upload_id)
        deadline = time.monotonic() + self._MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS

        while time.monotonic() < deadline:
            try:
                response = await self._request("GET", endpoint)
                status = response.get("status", "")
                if status == "done":
                    content_uri = response.get("content_uri", "")
                    if content_uri:
                        return response
                    raise Exception("Matrix async upload done but missing content_uri")
                if status in ("failed", "cancelled"):
                    error_msg = response.get("error", "unknown error")
                    raise Exception(f"Matrix async upload {status}: {error_msg}")
                # Still pending — wait and retry
                await asyncio.sleep(self._MEDIA_UPLOAD_POLL_INTERVAL_SECONDS)
            except MatrixAPIError:
                raise
            except Exception:
                await asyncio.sleep(self._MEDIA_UPLOAD_POLL_INTERVAL_SECONDS)

        raise Exception(
            f"Matrix async upload timed out after "
            f"{self._MEDIA_UPLOAD_POLL_TIMEOUT_SECONDS}s (upload_id={upload_id})"
        )

    @staticmethod
    def _should_try_next_media_upload_endpoint(
        status: int,
        endpoint_index: int,
        total_endpoints: int,
    ) -> bool:
        return status == 404 and endpoint_index < (total_endpoints - 1)
