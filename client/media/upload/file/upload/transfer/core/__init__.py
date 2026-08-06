"""Matrix media upload endpoint transfer and retry logic."""

from .attempt import MediaUploadTransferAttemptMixin
from .core import MediaUploadTransferOrchestratorMixin
from .retry import MediaUploadTransferRetryMixin
from .setup import MediaUploadTransferSetupMixin


class MediaUploadTransferCoreMixin(MediaUploadTransferOrchestratorMixin):
    """Upload a prepared file to Matrix endpoints."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaUploadTransferOrchestratorMixin,
    MediaUploadTransferRetryMixin,
    MediaUploadTransferAttemptMixin,
    MediaUploadTransferSetupMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaUploadTransferCoreMixin, _method_name, _method)


__all__ = [
    "MediaUploadTransferAttemptMixin",
    "MediaUploadTransferCoreMixin",
    "MediaUploadTransferOrchestratorMixin",
    "MediaUploadTransferRetryMixin",
    "MediaUploadTransferSetupMixin",
]
