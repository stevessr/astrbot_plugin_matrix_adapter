"""SAS MAC verification and failure handling.

Public symbols re-exported for backward compatibility.
"""

from .core import SASVerificationFlowMACCoreMixin
from .expected import SASVerificationFlowMACExpectedMixin
from .keys import SASVerificationFlowMACKeysMixin


class SASVerificationFlowMACMixin(
    SASVerificationFlowMACCoreMixin,
    SASVerificationFlowMACKeysMixin,
    SASVerificationFlowMACExpectedMixin,
):
    """校验对端 MAC 并在失败时发送取消。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowMACCoreMixin,
    SASVerificationFlowMACKeysMixin,
    SASVerificationFlowMACExpectedMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowMACMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowMACCoreMixin",
    "SASVerificationFlowMACExpectedMixin",
    "SASVerificationFlowMACKeysMixin",
    "SASVerificationFlowMACMixin",
]
