"""Byte-buffer Matrix media upload transfer with retry and async upload."""

from ..request import MediaUploadBytesRequestMixin
from ..result import MediaUploadBytesResultMixin
from .core import MediaUploadBytesTransferOrchestratorMixin
from .retry import MediaUploadBytesTransferRetryMixin


class MediaUploadBytesTransferCoreMixin(
    MediaUploadBytesTransferOrchestratorMixin,
    MediaUploadBytesRequestMixin,
    MediaUploadBytesResultMixin,
    MediaUploadBytesTransferRetryMixin,
):
    """Perform the HTTP media upload, with endpoint fallback and retries."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaUploadBytesTransferOrchestratorMixin,
    MediaUploadBytesRequestMixin,
    MediaUploadBytesResultMixin,
    MediaUploadBytesTransferRetryMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaUploadBytesTransferCoreMixin, _method_name, _method)


__all__ = [
    "MediaUploadBytesRequestMixin",
    "MediaUploadBytesResultMixin",
    "MediaUploadBytesTransferCoreMixin",
    "MediaUploadBytesTransferOrchestratorMixin",
    "MediaUploadBytesTransferRetryMixin",
]
