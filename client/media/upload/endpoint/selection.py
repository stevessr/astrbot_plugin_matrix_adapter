"""Matrix media upload endpoint selection operations."""

from ....path_utils import quote_path_segment


class MediaUploadEndpointSelectionMixin:
    """Select compatible Matrix media upload endpoints."""

    @staticmethod
    def _get_media_upload_endpoints() -> tuple[str, ...]:
        """Return preferred media upload endpoints in compatibility order.

        The Matrix spec (content repository) only defines
        ``POST /_matrix/media/v3/upload``; ``/_matrix/client/v1/media/*``
        covers MSC3916 read endpoints only. Keep the unversioned
        ``/_matrix/client/v1/media/upload`` as a 404 fallback for
        non-conforming homeservers that proxy it.
        """
        return (
            "/_matrix/media/v3/upload",
            "/_matrix/client/v1/media/upload",
        )

    @staticmethod
    def _get_media_upload_status_endpoint(upload_id: str) -> str:
        """Return the upload status endpoint for async upload (MSC2246)."""
        return f"/_matrix/client/v1/media/upload/{quote_path_segment(upload_id)}"

    @staticmethod
    def _should_try_next_media_upload_endpoint(
        status: int,
        endpoint_index: int,
        total_endpoints: int,
    ) -> bool:
        return status == 404 and endpoint_index < (total_endpoints - 1)
