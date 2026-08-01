from .msg import MatrixEventProcessorMessagesMixin
from .room import MatrixEventProcessorRoomDispatchMixin
from .states import MatrixEventProcessorStatesMixin


class MatrixEventProcessorMixin(
    MatrixEventProcessorMessagesMixin,
    MatrixEventProcessorStatesMixin,
    MatrixEventProcessorRoomDispatchMixin,
):
    """Combined event-processing mixin."""

    pass


__all__ = [
    "MatrixEventProcessorMessagesMixin",
    "MatrixEventProcessorStatesMixin",
    "MatrixEventProcessorRoomDispatchMixin",
    "MatrixEventProcessorMixin",
]
