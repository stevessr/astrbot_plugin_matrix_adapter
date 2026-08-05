"""Byte-buffer Matrix media upload transfer with retry and async upload."""

from .core import MediaUploadBytesTransferCoreMixin
from .request import MediaUploadBytesRequestMixin
from .result import MediaUploadBytesResultMixin


class MediaUploadBytesTransferMixin(
    MediaUploadBytesTransferCoreMixin,
):
    """Perform the HTTP media upload, with endpoint fallback and retries."""

    pass


# Preserve direct method attributes expected by parent mixins.
for _mixin in (
    MediaUploadBytesTransferCoreMixin,
    MediaUploadBytesRequestMixin,
    MediaUploadBytesResultMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaUploadBytesTransferMixin, _method_name, _method)


__all__ = [
    "MediaUploadBytesRequestMixin",
    "MediaUploadBytesResultMixin",
    "MediaUploadBytesTransferCoreMixin",
    "MediaUploadBytesTransferMixin",
]
