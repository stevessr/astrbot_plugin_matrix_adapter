"""Thumbnail fallback for full-size Matrix media downloads."""

from .attempt import MediaDownloadThumbnailAttemptMixin
from .core import MediaDownloadThumbnailFallbackOrchestratorMixin
from .endpoints import MediaDownloadThumbnailEndpointMixin


class MediaDownloadThumbnailFallbackMixin(
    MediaDownloadThumbnailFallbackOrchestratorMixin,
    MediaDownloadThumbnailAttemptMixin,
    MediaDownloadThumbnailEndpointMixin,
):
    """Retry media downloads through thumbnail endpoints."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaDownloadThumbnailFallbackOrchestratorMixin,
    MediaDownloadThumbnailAttemptMixin,
    MediaDownloadThumbnailEndpointMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadThumbnailFallbackMixin, _method_name, _method)


__all__ = [
    "MediaDownloadThumbnailAttemptMixin",
    "MediaDownloadThumbnailEndpointMixin",
    "MediaDownloadThumbnailFallbackMixin",
]
