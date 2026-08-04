"""Room event dispatch.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixEventProcessorRoomDispatchCoreMixin
from .members import MatrixEventProcessorRoomMembersMixin
from .state import MatrixEventProcessorRoomStateMixin


class MatrixEventProcessorRoomDispatchMixin(
    MatrixEventProcessorRoomDispatchCoreMixin,
    MatrixEventProcessorRoomMembersMixin,
    MatrixEventProcessorRoomStateMixin,
):
    """Mixin for room event dispatch."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorRoomDispatchCoreMixin,
    MatrixEventProcessorRoomMembersMixin,
    MatrixEventProcessorRoomStateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorRoomDispatchMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorRoomDispatchCoreMixin",
    "MatrixEventProcessorRoomDispatchMixin",
    "MatrixEventProcessorRoomMembersMixin",
    "MatrixEventProcessorRoomStateMixin",
]
