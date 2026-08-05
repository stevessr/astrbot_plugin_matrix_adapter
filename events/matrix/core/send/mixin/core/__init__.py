"""Matrix platform event message orchestration."""

from .adapt import MatrixPlatformEventSendAdaptMixin
from .core import MatrixPlatformEventSendCoreOrchestratorMixin
from .resolve import MatrixPlatformEventSendResolveMixin
from .reuse import MatrixPlatformEventSendReuseMixin
from .store import MatrixPlatformEventSendStoreMixin


class MatrixPlatformEventSendCoreMixin(
    MatrixPlatformEventSendCoreOrchestratorMixin,
    MatrixPlatformEventSendAdaptMixin,
    MatrixPlatformEventSendResolveMixin,
    MatrixPlatformEventSendReuseMixin,
    MatrixPlatformEventSendStoreMixin,
):
    """Send message chains and resolve Matrix thread/reply context."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventSendCoreOrchestratorMixin,
    MatrixPlatformEventSendAdaptMixin,
    MatrixPlatformEventSendResolveMixin,
    MatrixPlatformEventSendReuseMixin,
    MatrixPlatformEventSendStoreMixin,
):
    for _name, _member in _mixin.__dict__.items():
        if isinstance(_member, (staticmethod, classmethod)) or callable(_member):
            setattr(MatrixPlatformEventSendCoreMixin, _name, _member)


__all__ = [
    "MatrixPlatformEventSendAdaptMixin",
    "MatrixPlatformEventSendCoreMixin",
    "MatrixPlatformEventSendCoreOrchestratorMixin",
    "MatrixPlatformEventSendResolveMixin",
    "MatrixPlatformEventSendReuseMixin",
    "MatrixPlatformEventSendStoreMixin",
]
