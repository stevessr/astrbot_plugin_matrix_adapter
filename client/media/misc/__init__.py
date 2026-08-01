"""Composable shared helpers for Matrix media operations."""

from .mime import MediaMimeMixin
from .preview import MediaPreviewMixin
from .reader import MediaHashingReaderMixin
from .repository import MediaRepositoryMixin


class MediaMiscMixin(
    MediaMimeMixin,
    MediaRepositoryMixin,
    MediaPreviewMixin,
    MediaHashingReaderMixin,
):
    """Combined media helpers consumed by the HTTP client."""

    pass


__all__ = ["MediaMiscMixin"]
