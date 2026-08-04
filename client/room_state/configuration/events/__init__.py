"""Common room state-event configuration operations.

Public symbols re-exported for backward compatibility.
"""

from .access import RoomStateAccessMixin
from .aliases import RoomStateAliasesMixin
from .identity import RoomStateIdentityMixin


class RoomStateEventsMixin(
    RoomStateIdentityMixin,
    RoomStateAccessMixin,
    RoomStateAliasesMixin,
):
    """Set common room name, topic, access, and alias state events."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    RoomStateIdentityMixin,
    RoomStateAccessMixin,
    RoomStateAliasesMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(RoomStateEventsMixin, _method_name, _method)


__all__ = [
    "RoomStateAccessMixin",
    "RoomStateAliasesMixin",
    "RoomStateEventsMixin",
    "RoomStateIdentityMixin",
]
