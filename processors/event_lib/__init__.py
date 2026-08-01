from .members import MatrixEventProcessorMembers
from .msg import MatrixEventProcessorMessagesMixin
from .room import MatrixEventProcessorRoomDispatchMixin
from .states import MatrixEventProcessorStatesMixin
from .streams import MatrixEventProcessorStreams


class MatrixEventProcessorMixin(
    MatrixEventProcessorMessagesMixin,
    MatrixEventProcessorStatesMixin,
    MatrixEventProcessorRoomDispatchMixin,
    MatrixEventProcessorStreams,
    MatrixEventProcessorMembers,
):
    """Combined event-processing mixin."""

    pass


__all__ = [
    "MatrixEventProcessorMessagesMixin",
    "MatrixEventProcessorStatesMixin",
    "MatrixEventProcessorRoomDispatchMixin",
    "MatrixEventProcessorStreams",
    "MatrixEventProcessorMembers",
    "MatrixEventProcessorMixin",
]
