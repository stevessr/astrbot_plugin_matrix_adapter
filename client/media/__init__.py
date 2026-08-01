from .download import MediaDownloadMixin
from .misc import MediaMiscMixin
from .upload import MediaUploadMixin

__all__ = ["MediaUploadMixin", "MediaDownloadMixin", "MediaMiscMixin"]


class MediaMixin(
    MediaUploadMixin,
    MediaDownloadMixin,
    MediaMiscMixin,
):
    """Combined mixin."""

    pass
