"""Incoming SAS verification request handling.

Public symbols re-exported for backward compatibility.
"""

from .core import SASVerificationFlowRequestCoreMixin
from .dispatch import SASVerificationFlowRequestDispatchMixin
from .keys import SASVerificationFlowRequestKeysMixin


class SASVerificationFlowRequestMixin(
    SASVerificationFlowRequestCoreMixin,
    SASVerificationFlowRequestKeysMixin,
    SASVerificationFlowRequestDispatchMixin,
):
    """处理验证请求、设备指纹查询和验证模式分派。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowRequestCoreMixin,
    SASVerificationFlowRequestKeysMixin,
    SASVerificationFlowRequestDispatchMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowRequestMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowRequestCoreMixin",
    "SASVerificationFlowRequestDispatchMixin",
    "SASVerificationFlowRequestKeysMixin",
    "SASVerificationFlowRequestMixin",
]
