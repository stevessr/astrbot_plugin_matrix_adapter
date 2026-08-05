"""Matrix media upload endpoint transfer and retry logic."""

from .core import MediaUploadTransferCoreMixin
from .request import MediaUploadTransferRequestMixin
from .result import MediaUploadTransferResultMixin


class MediaUploadTransferMixin(MediaUploadTransferCoreMixin):
    """Upload a prepared file to Matrix endpoints."""

    pass


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaUploadTransferCoreMixin,
    MediaUploadTransferRequestMixin,
    MediaUploadTransferResultMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaUploadTransferMixin, _method_name, _method)


__all__ = [
    "MediaUploadTransferCoreMixin",
    "MediaUploadTransferMixin",
    "MediaUploadTransferRequestMixin",
    "MediaUploadTransferResultMixin",
]
