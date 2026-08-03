"""Composable Matrix media upload retry policy operations."""

from typing import Any  # noqa: F401

import aiohttp  # noqa: F401

from .classification import MediaUploadRetryClassificationMixin
from .delay import MediaUploadRetryDelayMixin


class MediaUploadRetryMixin(
    MediaUploadRetryDelayMixin,
    MediaUploadRetryClassificationMixin,
):
    """Calculate retry delays and classify retryable responses."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MediaUploadRetryMixin._coerce_retry_after_seconds = MediaUploadRetryDelayMixin.__dict__[
    "_coerce_retry_after_seconds"
]
MediaUploadRetryMixin._extract_retry_after_seconds = (
    MediaUploadRetryDelayMixin.__dict__["_extract_retry_after_seconds"]
)
MediaUploadRetryMixin._compute_retry_delay = MediaUploadRetryDelayMixin.__dict__[
    "_compute_retry_delay"
]
MediaUploadRetryMixin._should_retry_http_status = (
    MediaUploadRetryClassificationMixin.__dict__["_should_retry_http_status"]
)


__all__ = ["Any", "MediaUploadRetryMixin", "aiohttp"]
