"""SAS ephemeral key exchange and shared-secret calculation.

Public symbols re-exported for backward compatibility.
"""

from .commitment import SASVerificationFlowKeyCommitmentMixin
from .core import SASVerificationFlowKeyCoreMixin
from .sas import SASVerificationFlowKeySasMixin


class SASVerificationFlowKeyExchangeMixin(
    SASVerificationFlowKeyCoreMixin,
    SASVerificationFlowKeyCommitmentMixin,
    SASVerificationFlowKeySasMixin,
):
    """处理 commitment、公钥交换和 SAS 共享密钥计算。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    SASVerificationFlowKeyCoreMixin,
    SASVerificationFlowKeyCommitmentMixin,
    SASVerificationFlowKeySasMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowKeyExchangeMixin, _method_name, _method)


__all__ = [
    "SASVerificationFlowKeyCommitmentMixin",
    "SASVerificationFlowKeyCoreMixin",
    "SASVerificationFlowKeyExchangeMixin",
    "SASVerificationFlowKeySasMixin",
]
