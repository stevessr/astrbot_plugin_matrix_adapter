"""Full-size Matrix media download flow.

Public symbols re-exported for backward compatibility.
"""

from .attempt import MediaDownloadAttemptMixin
from .core import MediaDownloadPrimaryCoreMixin


class MediaDownloadPrimaryMixin(
    MediaDownloadPrimaryCoreMixin,
    MediaDownloadAttemptMixin,
):
    """Download full-size media from Matrix."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaDownloadPrimaryCoreMixin,
    MediaDownloadAttemptMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadPrimaryMixin, _method_name, _method)


__all__ = [
    "MediaDownloadAttemptMixin",
    "MediaDownloadPrimaryCoreMixin",
    "MediaDownloadPrimaryMixin",
]
