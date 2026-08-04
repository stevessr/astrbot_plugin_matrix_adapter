"""Room message and custom event send operations.

Public symbols re-exported for backward compatibility.
"""

from .event import RoomEventSendMixin
from .message import RoomMessageSendMixin


class MessageRoomContentSendMixin(
    RoomMessageSendMixin,
    RoomEventSendMixin,
):
    """Send room messages and custom room events."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    RoomMessageSendMixin,
    RoomEventSendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MessageRoomContentSendMixin, _method_name, _method)


__all__ = [
    "MessageRoomContentSendMixin",
    "RoomEventSendMixin",
    "RoomMessageSendMixin",
]
