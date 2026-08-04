"""Outgoing Matrix room-key request lifecycle.

Public symbols re-exported for backward compatibility.
"""

from .cancel import E2EEManagerRequestsRoomKeyCancelMixin
from .core import E2EEManagerRequestsRoomKeyCoreMixin
from .throttle import E2EEManagerRequestsRoomKeyThrottleMixin


class E2EEManagerRequestsRoomKeyMixin(
    E2EEManagerRequestsRoomKeyCoreMixin,
    E2EEManagerRequestsRoomKeyThrottleMixin,
    E2EEManagerRequestsRoomKeyCancelMixin,
):
    """发送、节流和取消 m.room_key_request。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    E2EEManagerRequestsRoomKeyCoreMixin,
    E2EEManagerRequestsRoomKeyThrottleMixin,
    E2EEManagerRequestsRoomKeyCancelMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerRequestsRoomKeyMixin, _method_name, _method)


__all__ = [
    "E2EEManagerRequestsRoomKeyCancelMixin",
    "E2EEManagerRequestsRoomKeyCoreMixin",
    "E2EEManagerRequestsRoomKeyMixin",
    "E2EEManagerRequestsRoomKeyThrottleMixin",
]
