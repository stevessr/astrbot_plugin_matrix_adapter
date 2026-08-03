"""Composable Matrix media upload endpoint operations."""

import asyncio  # noqa: F401
import time  # noqa: F401
from typing import Any  # noqa: F401

from ....base import MatrixAPIError  # noqa: F401
from ....path_utils import quote_path_segment  # noqa: F401
from .polling import MediaUploadEndpointPollingMixin
from .selection import MediaUploadEndpointSelectionMixin


class MediaUploadEndpointMixin(
    MediaUploadEndpointSelectionMixin,
    MediaUploadEndpointPollingMixin,
):
    """Select upload endpoints and poll asynchronous upload status."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaUploadEndpointMixin._get_media_upload_endpoints = (
    MediaUploadEndpointSelectionMixin.__dict__["_get_media_upload_endpoints"]
)
MediaUploadEndpointMixin._get_media_upload_status_endpoint = (
    MediaUploadEndpointSelectionMixin.__dict__["_get_media_upload_status_endpoint"]
)
MediaUploadEndpointMixin._poll_upload_status = MediaUploadEndpointPollingMixin.__dict__[
    "_poll_upload_status"
]
MediaUploadEndpointMixin._should_try_next_media_upload_endpoint = (
    MediaUploadEndpointSelectionMixin.__dict__["_should_try_next_media_upload_endpoint"]
)


__all__ = [
    "Any",
    "MatrixAPIError",
    "MediaUploadEndpointMixin",
    "asyncio",
    "quote_path_segment",
    "time",
]
