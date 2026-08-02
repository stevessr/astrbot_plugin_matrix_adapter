"""Composable direct and in-room verification event handlers."""

from ..constants import VODOZEMAC_SAS_AVAILABLE
from .dispatch import SASVerificationEventDispatchMixin
from .room_dispatch import SASVerificationRoomEventDispatchMixin
from .room_request import SASVerificationRoomRequestMixin


class SASVerificationEventMixin(
    SASVerificationEventDispatchMixin,
    SASVerificationRoomEventDispatchMixin,
    SASVerificationRoomRequestMixin,
):
    """处理 to-device 与房间内 Matrix 验证事件。"""

    pass


for _method_name in (
    "handle_verification_event",
    "handle_in_room_verification_event",
    "_handle_in_room_request",
):
    for _mixin in (
        SASVerificationEventDispatchMixin,
        SASVerificationRoomEventDispatchMixin,
        SASVerificationRoomRequestMixin,
    ):
        if hasattr(_mixin, _method_name):
            setattr(
                SASVerificationEventMixin,
                _method_name,
                getattr(_mixin, _method_name),
            )
            break

__all__ = [
    "SASVerificationEventDispatchMixin",
    "SASVerificationEventMixin",
    "SASVerificationRoomEventDispatchMixin",
    "SASVerificationRoomRequestMixin",
    "VODOZEMAC_SAS_AVAILABLE",
]
