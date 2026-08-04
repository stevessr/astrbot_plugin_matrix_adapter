"""Byte-buffer Matrix media upload operation.

Public symbols re-exported for backward compatibility.
"""

from .core import MediaUploadBytesCoreMixin
from .transfer import MediaUploadBytesTransferMixin


class MediaUploadBytesOperationMixin(
    MediaUploadBytesCoreMixin,
    MediaUploadBytesTransferMixin,
):
    """Upload in-memory media with retry and async-upload support."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    MediaUploadBytesCoreMixin,
    MediaUploadBytesTransferMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaUploadBytesOperationMixin, _method_name, _method)


__all__ = [
    "MediaUploadBytesCoreMixin",
    "MediaUploadBytesOperationMixin",
    "MediaUploadBytesTransferMixin",
]
