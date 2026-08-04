"""In-room verification event routing and session ownership checks.

Public symbols re-exported for backward compatibility.
"""

from .core import SASVerificationRoomEventDispatchCoreMixin
from .own import SASVerificationRoomEventDispatchOwnMixin
from .txn import SASVerificationRoomEventDispatchTxnMixin


class SASVerificationRoomEventDispatchMixin(
    SASVerificationRoomEventDispatchCoreMixin,
    SASVerificationRoomEventDispatchTxnMixin,
    SASVerificationRoomEventDispatchOwnMixin,
):
    """解析房间内事件关系、处理设备接管并路由事件。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationRoomEventDispatchCoreMixin,
    SASVerificationRoomEventDispatchTxnMixin,
    SASVerificationRoomEventDispatchOwnMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationRoomEventDispatchMixin, _method_name, _method)


__all__ = [
    "SASVerificationRoomEventDispatchCoreMixin",
    "SASVerificationRoomEventDispatchMixin",
    "SASVerificationRoomEventDispatchOwnMixin",
    "SASVerificationRoomEventDispatchTxnMixin",
]
