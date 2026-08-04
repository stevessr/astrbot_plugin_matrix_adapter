"""Pinned-event state operations for Matrix rooms.

Public symbols re-exported for backward compatibility.
"""

from .core import RoomPinnedStateMixin
from .mutate import RoomPinnedMutateMixin
from .normalize import normalize_pinned_event_ids


class RoomPinnedEventsMixin(
    RoomPinnedStateMixin,
    RoomPinnedMutateMixin,
):
    """Normalize, read, and update a room's pinned event list."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    RoomPinnedStateMixin,
    RoomPinnedMutateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(RoomPinnedEventsMixin, _method_name, _method)


# Backward-compatible static helper on the composed mixin.
RoomPinnedEventsMixin._normalize_pinned_event_ids = staticmethod(
    normalize_pinned_event_ids
)


__all__ = [
    "RoomPinnedEventsMixin",
    "RoomPinnedMutateMixin",
    "RoomPinnedStateMixin",
    "normalize_pinned_event_ids",
]
