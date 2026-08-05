"""Room forgetting, upgrading, and knock-management operations."""

from .knock import RoomKnockMixin
from .transition import RoomTransitionMixin


class RoomLifecycleMixin(
    RoomTransitionMixin,
    RoomKnockMixin,
):
    """Manage room lifecycle transitions and knock requests."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    RoomTransitionMixin,
    RoomKnockMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(RoomLifecycleMixin, _method_name, _method)


__all__ = [
    "RoomKnockMixin",
    "RoomLifecycleMixin",
    "RoomTransitionMixin",
]
