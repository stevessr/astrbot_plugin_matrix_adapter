"""Single-endpoint media download attempt loop with retries."""

from .core import MediaDownloadAttemptOrchestratorMixin
from .error import MediaDownloadAttemptErrorMixin
from .success import MediaDownloadAttemptSuccessMixin
from .throttle import MediaDownloadAttemptThrottleMixin


class MediaDownloadAttemptMixin(MediaDownloadAttemptOrchestratorMixin):
    """Retry-and-breaker aware download attempts against one endpoint."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaDownloadAttemptOrchestratorMixin,
    MediaDownloadAttemptErrorMixin,
    MediaDownloadAttemptSuccessMixin,
    MediaDownloadAttemptThrottleMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadAttemptMixin, _method_name, _method)


__all__ = [
    "MediaDownloadAttemptErrorMixin",
    "MediaDownloadAttemptMixin",
    "MediaDownloadAttemptOrchestratorMixin",
    "MediaDownloadAttemptSuccessMixin",
    "MediaDownloadAttemptThrottleMixin",
]
