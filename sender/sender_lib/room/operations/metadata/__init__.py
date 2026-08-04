"""Room configuration, directory, pins, and unread metadata operations.

Public symbols re-exported for backward compatibility.
"""

from .aliases import SenderRoomAliasesMixin
from .config import SenderRoomConfigMixin
from .directory import SenderRoomDirectoryMixin
from .pins import SenderRoomPinsMixin
from .unread import SenderRoomUnreadMixin


class SenderRoomMetadataMixin(
    SenderRoomConfigMixin,
    SenderRoomAliasesMixin,
    SenderRoomDirectoryMixin,
    SenderRoomPinsMixin,
    SenderRoomUnreadMixin,
):
    """Delegates room configuration and metadata operations."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    SenderRoomConfigMixin,
    SenderRoomAliasesMixin,
    SenderRoomDirectoryMixin,
    SenderRoomPinsMixin,
    SenderRoomUnreadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SenderRoomMetadataMixin, _method_name, _method)


__all__ = [
    "SenderRoomAliasesMixin",
    "SenderRoomConfigMixin",
    "SenderRoomDirectoryMixin",
    "SenderRoomMetadataMixin",
    "SenderRoomPinsMixin",
    "SenderRoomUnreadMixin",
]
