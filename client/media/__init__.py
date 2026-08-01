from .upload import MediaUploadMixin
from .download import MediaDownloadMixin
from .misc import MediaMiscMixin


__all__ = ['MediaUploadMixin', 'MediaDownloadMixin', 'MediaMiscMixin']

class MediaMixin(
    MediaUploadMixin,
    MediaDownloadMixin,
    MediaMiscMixin,
):
    """Combined mixin."""
    pass
