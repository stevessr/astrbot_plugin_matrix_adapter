"""Composable Matrix event processor implementation."""

from ..event_lib.members import MatrixEventProcessorMembers
from ..event_lib.msg import MatrixEventProcessorMessagesMixin
from ..event_lib.room import MatrixEventProcessorRoomDispatchMixin
from ..event_lib.states import MatrixEventProcessorStatesMixin
from ..event_lib.streams import MatrixEventProcessorStreams
from .state import MatrixEventProcessorStateMixin
from .to_device import MatrixEventProcessorToDeviceMixin


class MatrixEventProcessor(
    MatrixEventProcessorStateMixin,
    MatrixEventProcessorMessagesMixin,
    MatrixEventProcessorStatesMixin,
    MatrixEventProcessorRoomDispatchMixin,
    MatrixEventProcessorStreams,
    MatrixEventProcessorMembers,
    MatrixEventProcessorToDeviceMixin,
):
    """Process Matrix events through specialized domain mixins."""

    pass


__all__ = ["MatrixEventProcessor"]
