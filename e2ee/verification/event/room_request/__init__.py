"""In-room verification request handling.

Public symbols re-exported for backward compatibility.
"""

from .core import SASVerificationRoomRequestCoreMixin
from .policy import SASVerificationRoomRequestPolicyMixin
from .trust import SASVerificationRoomRequestTrustMixin


class SASVerificationRoomRequestMixin(
    SASVerificationRoomRequestCoreMixin,
    SASVerificationRoomRequestTrustMixin,
    SASVerificationRoomRequestPolicyMixin,
):
    """处理房间内验证请求、设备信任查询和自动确认策略。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationRoomRequestCoreMixin,
    SASVerificationRoomRequestTrustMixin,
    SASVerificationRoomRequestPolicyMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationRoomRequestMixin, _method_name, _method)


__all__ = [
    "SASVerificationRoomRequestCoreMixin",
    "SASVerificationRoomRequestMixin",
    "SASVerificationRoomRequestPolicyMixin",
    "SASVerificationRoomRequestTrustMixin",
]
