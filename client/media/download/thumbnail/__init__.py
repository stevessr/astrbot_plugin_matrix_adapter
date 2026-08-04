"""Matrix media thumbnail download operation.

Public symbols re-exported for backward compatibility.
"""

from .core import MediaDownloadThumbnailCoreMixin
from .transfer import MediaDownloadThumbnailTransferMixin


class MediaDownloadThumbnailMixin(
    MediaDownloadThumbnailCoreMixin,
    MediaDownloadThumbnailTransferMixin,
):
    """Download thumbnails with the shared flow-control primitives."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    MediaDownloadThumbnailCoreMixin,
    MediaDownloadThumbnailTransferMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadThumbnailMixin, _method_name, _method)


__all__ = [
    "MediaDownloadThumbnailCoreMixin",
    "MediaDownloadThumbnailMixin",
    "MediaDownloadThumbnailTransferMixin",
]
