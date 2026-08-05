"""Full-size Matrix media download orchestration."""

from .attempt import MediaDownloadPrimaryAttemptMixin
from .core import MediaDownloadPrimaryOrchestratorMixin
from .endpoints import MediaDownloadPrimaryEndpointMixin
from .setup import MediaDownloadPrimarySetupMixin


class MediaDownloadPrimaryCoreMixin(
    MediaDownloadPrimaryOrchestratorMixin,
    MediaDownloadPrimarySetupMixin,
    MediaDownloadPrimaryEndpointMixin,
    MediaDownloadPrimaryAttemptMixin,
):
    """Download full-size media from Matrix."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MediaDownloadPrimaryOrchestratorMixin,
    MediaDownloadPrimarySetupMixin,
    MediaDownloadPrimaryEndpointMixin,
    MediaDownloadPrimaryAttemptMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MediaDownloadPrimaryCoreMixin, _method_name, _method)


__all__ = [
    "MediaDownloadPrimaryCoreMixin",
    "MediaDownloadPrimaryOrchestratorMixin",
    "MediaDownloadPrimarySetupMixin",
    "MediaDownloadPrimaryEndpointMixin",
    "MediaDownloadPrimaryAttemptMixin",
]
