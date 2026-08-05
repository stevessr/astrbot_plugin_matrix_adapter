"""Room-section dispatch for sync responses."""

from .core import MatrixSyncManagerEventRoutingRoomsOrchestratorMixin
from .invite import MatrixSyncManagerEventRoutingRoomsInviteMixin
from .join import MatrixSyncManagerEventRoutingRoomsJoinMixin
from .knock import MatrixSyncManagerEventRoutingRoomsKnockMixin
from .leave import MatrixSyncManagerEventRoutingRoomsLeaveMixin


class MatrixSyncManagerEventRoutingRoomsMixin(
    MatrixSyncManagerEventRoutingRoomsOrchestratorMixin,
    MatrixSyncManagerEventRoutingRoomsJoinMixin,
    MatrixSyncManagerEventRoutingRoomsInviteMixin,
    MatrixSyncManagerEventRoutingRoomsLeaveMixin,
    MatrixSyncManagerEventRoutingRoomsKnockMixin,
):
    """Dispatch per-room sync response fields to callbacks."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixSyncManagerEventRoutingRoomsOrchestratorMixin,
    MatrixSyncManagerEventRoutingRoomsJoinMixin,
    MatrixSyncManagerEventRoutingRoomsInviteMixin,
    MatrixSyncManagerEventRoutingRoomsLeaveMixin,
    MatrixSyncManagerEventRoutingRoomsKnockMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixSyncManagerEventRoutingRoomsMixin, _method_name, _method)


__all__ = [
    "MatrixSyncManagerEventRoutingRoomsMixin",
    "MatrixSyncManagerEventRoutingRoomsOrchestratorMixin",
    "MatrixSyncManagerEventRoutingRoomsJoinMixin",
    "MatrixSyncManagerEventRoutingRoomsInviteMixin",
    "MatrixSyncManagerEventRoutingRoomsLeaveMixin",
    "MatrixSyncManagerEventRoutingRoomsKnockMixin",
]
