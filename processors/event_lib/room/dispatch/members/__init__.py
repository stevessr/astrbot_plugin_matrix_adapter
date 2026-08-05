"""Room member loading for event dispatch."""

from .core import MatrixEventProcessorRoomMembersOrchestratorMixin
from .fallback import MatrixEventProcessorRoomMembersFallbackMixin
from .fetch import MatrixEventProcessorRoomMembersFetchMixin
from .persist import MatrixEventProcessorRoomMembersPersistMixin


class MatrixEventProcessorRoomMembersMixin(
    MatrixEventProcessorRoomMembersOrchestratorMixin,
    MatrixEventProcessorRoomMembersFetchMixin,
    MatrixEventProcessorRoomMembersPersistMixin,
    MatrixEventProcessorRoomMembersFallbackMixin,
):
    """Load and persist room members for dispatch."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorRoomMembersOrchestratorMixin,
    MatrixEventProcessorRoomMembersFetchMixin,
    MatrixEventProcessorRoomMembersPersistMixin,
    MatrixEventProcessorRoomMembersFallbackMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorRoomMembersMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorRoomMembersMixin",
    "MatrixEventProcessorRoomMembersOrchestratorMixin",
    "MatrixEventProcessorRoomMembersFetchMixin",
    "MatrixEventProcessorRoomMembersPersistMixin",
    "MatrixEventProcessorRoomMembersFallbackMixin",
]
