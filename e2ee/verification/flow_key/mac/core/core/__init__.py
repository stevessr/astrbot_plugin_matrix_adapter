"""SAS MAC verification orchestration."""

from .core import SASVerificationFlowMACOrchestratorMixin
from .finish import SASVerificationFlowMACFinishMixin
from .guard import SASVerificationFlowMACGuardMixin
from .info import SASVerificationFlowMACInfoMixin
from .keycheck import SASVerificationFlowMACKeyCheckMixin
from .record import SASVerificationFlowMACRecordMixin


class SASVerificationFlowMACHandleMixin(SASVerificationFlowMACOrchestratorMixin):
    """校验对端 MAC 并在失败时发送取消。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowMACOrchestratorMixin,
    SASVerificationFlowMACFinishMixin,
    SASVerificationFlowMACKeyCheckMixin,
    SASVerificationFlowMACRecordMixin,
    SASVerificationFlowMACGuardMixin,
    SASVerificationFlowMACInfoMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowMACHandleMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowMACFinishMixin",
    "SASVerificationFlowMACGuardMixin",
    "SASVerificationFlowMACHandleMixin",
    "SASVerificationFlowMACInfoMixin",
    "SASVerificationFlowMACKeyCheckMixin",
    "SASVerificationFlowMACOrchestratorMixin",
    "SASVerificationFlowMACRecordMixin",
]
