"""SAS MAC verification and failure handling."""

from .cancel import SASVerificationFlowMACCancelMixin
from .core import SASVerificationFlowMACHandleMixin
from .done import SASVerificationFlowMACDoneMixin
from .verify import SASVerificationFlowMACVerifyMixin


class SASVerificationFlowMACCoreMixin(SASVerificationFlowMACHandleMixin):
    """校验对端 MAC 并在失败时发送取消。"""

    pass


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowMACHandleMixin,
    SASVerificationFlowMACCancelMixin,
    SASVerificationFlowMACVerifyMixin,
    SASVerificationFlowMACDoneMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowMACCoreMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowMACCancelMixin",
    "SASVerificationFlowMACCoreMixin",
    "SASVerificationFlowMACDoneMixin",
    "SASVerificationFlowMACHandleMixin",
    "SASVerificationFlowMACVerifyMixin",
]
