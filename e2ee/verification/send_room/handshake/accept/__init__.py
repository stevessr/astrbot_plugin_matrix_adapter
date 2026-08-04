"""In-room SAS accept negotiation and commitment construction."""

from .core import SASVerificationSendRoomAcceptCoreMixin
from .key import SASVerificationSendRoomAcceptKeyMixin


class SASVerificationSendRoomAcceptMixin(
    SASVerificationSendRoomAcceptCoreMixin,
    SASVerificationSendRoomAcceptKeyMixin,
):
    """协商房间内 SAS 算法并构造 accept 消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    SASVerificationSendRoomAcceptCoreMixin,
    SASVerificationSendRoomAcceptKeyMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationSendRoomAcceptMixin, _name, _method)

__all__ = ["SASVerificationSendRoomAcceptMixin"]
