"""Live message edit-loop state machine."""

from .breaks import MatrixPlatformEventMessagesLiveBreakMixin
from .core import MatrixPlatformEventMessagesLiveOrchestratorMixin
from .finalize import MatrixPlatformEventMessagesLiveFinalizeMixin
from .flush import MatrixPlatformEventMessagesLiveFlushMixin


class MatrixPlatformEventMessagesLiveMixin(
    MatrixPlatformEventMessagesLiveOrchestratorMixin,
    MatrixPlatformEventMessagesLiveBreakMixin,
    MatrixPlatformEventMessagesLiveFlushMixin,
    MatrixPlatformEventMessagesLiveFinalizeMixin,
):
    """Emit streaming chunks via MSC4357 marker and ``m.replace`` edits."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixPlatformEventMessagesLiveOrchestratorMixin,
    MatrixPlatformEventMessagesLiveBreakMixin,
    MatrixPlatformEventMessagesLiveFlushMixin,
    MatrixPlatformEventMessagesLiveFinalizeMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixPlatformEventMessagesLiveMixin, _method_name, _method)


__all__ = [
    "MatrixPlatformEventMessagesLiveMixin",
    "MatrixPlatformEventMessagesLiveOrchestratorMixin",
    "MatrixPlatformEventMessagesLiveBreakMixin",
    "MatrixPlatformEventMessagesLiveFlushMixin",
    "MatrixPlatformEventMessagesLiveFinalizeMixin",
]
