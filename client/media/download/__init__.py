"""Composable Matrix media download mixins."""

from .file import MediaDownloadFileMixin
from .flow import MediaDownloadFlowControlMixin
from .response import MediaDownloadResponseMixin
from .thumbnail import MediaDownloadThumbnailMixin


class MediaDownloadMixin(
    MediaDownloadFileMixin,
    MediaDownloadThumbnailMixin,
    MediaDownloadResponseMixin,
    MediaDownloadFlowControlMixin,
):
    """Combined download API preserving the historical client mixin."""


__all__ = [
    "MediaDownloadFileMixin",
    "MediaDownloadFlowControlMixin",
    "MediaDownloadMixin",
    "MediaDownloadResponseMixin",
    "MediaDownloadThumbnailMixin",
]
