"""Composable in-room Matrix verification sender."""

from ..constants import VODOZEMAC_SAS_AVAILABLE
from .handshake import SASVerificationSendRoomHandshakeMixin
from .messages import SASVerificationSendRoomMessagesMixin
from .transport import SASVerificationSendRoomTransportMixin


class SASVerificationSendRoomMixin(
    SASVerificationSendRoomTransportMixin,
    SASVerificationSendRoomHandshakeMixin,
    SASVerificationSendRoomMessagesMixin,
):
    """发送房间内验证事件、握手和完成消息。"""

    pass


for _method_name in (
    "_send_in_room_event",
    "_send_in_room_ready",
    "_send_in_room_accept",
    "_send_in_room_key",
    "_send_in_room_mac",
    "_send_in_room_done",
    "_send_in_room_cancel",
):
    for _mixin in (
        SASVerificationSendRoomTransportMixin,
        SASVerificationSendRoomHandshakeMixin,
        SASVerificationSendRoomMessagesMixin,
    ):
        if hasattr(_mixin, _method_name):
            setattr(
                SASVerificationSendRoomMixin,
                _method_name,
                getattr(_mixin, _method_name),
            )
            break

for _method_name in ("_normalize_algorithm_values", "_pick_algorithm"):
    setattr(
        SASVerificationSendRoomMixin,
        _method_name,
        staticmethod(getattr(SASVerificationSendRoomTransportMixin, _method_name)),
    )

__all__ = [
    "SASVerificationSendRoomHandshakeMixin",
    "SASVerificationSendRoomMessagesMixin",
    "SASVerificationSendRoomMixin",
    "SASVerificationSendRoomTransportMixin",
    "VODOZEMAC_SAS_AVAILABLE",
]
