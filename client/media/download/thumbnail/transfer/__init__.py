"""Matrix media thumbnail HTTP transfer with retries and flow control."""

from .core import MediaDownloadThumbnailOrchestratorMixin
from .success import MediaDownloadThumbnailSuccessMixin
from .throttle import MediaDownloadThumbnailThrottleMixin


class MediaDownloadThumbnailTransferMixin(MediaDownloadThumbnailOrchestratorMixin):
    """Perform the thumbnail download with retry and flow-control primitives."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaDownloadThumbnailOrchestratorMixin,
    MediaDownloadThumbnailSuccessMixin,
    MediaDownloadThumbnailThrottleMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadThumbnailTransferMixin, _method_name, _method)


__all__ = [
    "MediaDownloadThumbnailOrchestratorMixin",
    "MediaDownloadThumbnailSuccessMixin",
    "MediaDownloadThumbnailThrottleMixin",
    "MediaDownloadThumbnailTransferMixin",
]
