"""Preparing self-verification QR codes for same-account peers."""

from .core import SASVerificationFlowQRPrepareOrchestratorMixin
from .guard import SASVerificationFlowQRPrepareGuardMixin
from .keys import SASVerificationFlowQRPrepareKeysMixin
from .mode import SASVerificationFlowQRPrepareModeMixin
from .payload import SASVerificationFlowQRPreparePayloadMixin


class SASVerificationFlowQRPrepareMixin(
    SASVerificationFlowQRPrepareOrchestratorMixin,
    SASVerificationFlowQRPrepareGuardMixin,
    SASVerificationFlowQRPrepareKeysMixin,
    SASVerificationFlowQRPrepareModeMixin,
    SASVerificationFlowQRPreparePayloadMixin,
):
    """准备同账号设备之间的自验证二维码。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowQRPrepareOrchestratorMixin,
    SASVerificationFlowQRPrepareGuardMixin,
    SASVerificationFlowQRPrepareKeysMixin,
    SASVerificationFlowQRPrepareModeMixin,
    SASVerificationFlowQRPreparePayloadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowQRPrepareMixin, _method_name, _method)


__all__ = ["SASVerificationFlowQRPrepareMixin"]
