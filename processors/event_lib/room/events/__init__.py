"""Individual room event handling operations."""

from .call import MatrixEventProcessorRoomCallMixin
from .core import MatrixEventProcessorRoomEventsCoreMixin
from .membership import MatrixEventProcessorRoomMembershipMixin
from .message import MatrixEventProcessorRoomMessageMixin
from .redaction import MatrixEventProcessorRoomRedactionMixin
from .state import MatrixEventProcessorRoomStateUpdateMixin
from .verification import MatrixEventProcessorRoomVerificationMixin


class MatrixEventProcessorRoomEventsMixin(
    MatrixEventProcessorRoomEventsCoreMixin,
    MatrixEventProcessorRoomMembershipMixin,
    MatrixEventProcessorRoomStateUpdateMixin,
    MatrixEventProcessorRoomVerificationMixin,
    MatrixEventProcessorRoomCallMixin,
    MatrixEventProcessorRoomRedactionMixin,
    MatrixEventProcessorRoomMessageMixin,
):
    """Handle individual Matrix room events."""

    pass


# Preserve direct method attributes expected by parent mixins.
for _mixin in (
    MatrixEventProcessorRoomEventsCoreMixin,
    MatrixEventProcessorRoomMembershipMixin,
    MatrixEventProcessorRoomStateUpdateMixin,
    MatrixEventProcessorRoomVerificationMixin,
    MatrixEventProcessorRoomCallMixin,
    MatrixEventProcessorRoomRedactionMixin,
    MatrixEventProcessorRoomMessageMixin,
):
    for _name, _m in _mixin.__dict__.items():
        if _name.startswith("__"):
            continue
        if isinstance(_m, (staticmethod, classmethod)) or callable(_m):
            setattr(MatrixEventProcessorRoomEventsMixin, _name, _m)


__all__ = ["MatrixEventProcessorRoomEventsMixin"]
