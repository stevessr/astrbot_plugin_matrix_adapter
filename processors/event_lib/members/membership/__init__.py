"""Matrix room membership change handling.

Public symbols re-exported for backward compatibility.
"""

from .core import MatrixEventProcessorMembershipCoreMixin
from .invite import MatrixEventProcessorMembershipInviteMixin
from .join import MatrixEventProcessorMembershipJoinMixin
from .knock import MatrixEventProcessorMembershipKnockMixin
from .leave import MatrixEventProcessorMembershipLeaveMixin


class MatrixEventProcessorMembershipChangesMixin(
    MatrixEventProcessorMembershipCoreMixin,
    MatrixEventProcessorMembershipJoinMixin,
    MatrixEventProcessorMembershipInviteMixin,
    MatrixEventProcessorMembershipKnockMixin,
    MatrixEventProcessorMembershipLeaveMixin,
):
    """Handle membership changes and update room/profile storage."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixEventProcessorMembershipCoreMixin,
    MatrixEventProcessorMembershipJoinMixin,
    MatrixEventProcessorMembershipInviteMixin,
    MatrixEventProcessorMembershipKnockMixin,
    MatrixEventProcessorMembershipLeaveMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixEventProcessorMembershipChangesMixin, _method_name, _method)


__all__ = [
    "MatrixEventProcessorMembershipChangesMixin",
    "MatrixEventProcessorMembershipCoreMixin",
    "MatrixEventProcessorMembershipInviteMixin",
    "MatrixEventProcessorMembershipJoinMixin",
    "MatrixEventProcessorMembershipKnockMixin",
    "MatrixEventProcessorMembershipLeaveMixin",
]
