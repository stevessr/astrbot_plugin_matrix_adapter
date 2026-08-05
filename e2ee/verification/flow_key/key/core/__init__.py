"""SAS key-exchange orchestration."""

from .compute import SASVerificationFlowKeyComputeMixin
from .core import SASVerificationFlowKeyCoreOrchestratorMixin
from .exchange import SASVerificationFlowKeyExchangeMixin
from .mac import SASVerificationFlowKeyMacMixin
from .validate import SASVerificationFlowKeyValidateMixin


class SASVerificationFlowKeyCoreMixin(
    SASVerificationFlowKeyCoreOrchestratorMixin,
    SASVerificationFlowKeyValidateMixin,
    SASVerificationFlowKeyExchangeMixin,
    SASVerificationFlowKeyComputeMixin,
    SASVerificationFlowKeyMacMixin,
):
    """处理 commitment、公钥交换和 SAS 共享密钥计算。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowKeyCoreOrchestratorMixin,
    SASVerificationFlowKeyValidateMixin,
    SASVerificationFlowKeyExchangeMixin,
    SASVerificationFlowKeyComputeMixin,
    SASVerificationFlowKeyMacMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowKeyCoreMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowKeyComputeMixin",
    "SASVerificationFlowKeyCoreMixin",
    "SASVerificationFlowKeyCoreOrchestratorMixin",
    "SASVerificationFlowKeyExchangeMixin",
    "SASVerificationFlowKeyMacMixin",
    "SASVerificationFlowKeyValidateMixin",
]
