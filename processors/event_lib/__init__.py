from .msg import MatrixEventProcessorMessagesMixin
from .states import MatrixEventProcessorStatesMixin
from .room import MatrixEventProcessorRoomDispatchMixin


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
