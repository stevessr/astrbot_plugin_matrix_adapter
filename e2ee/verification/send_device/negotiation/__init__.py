"""Verification method negotiation and identity-key selection."""

from .algorithms import SASVerificationSendDeviceNegotiationAlgorithmsMixin
from .keys import SASVerificationSendDeviceNegotiationKeysMixin
from .methods import SASVerificationSendDeviceNegotiationMethodsMixin
from .trust import SASVerificationSendDeviceNegotiationTrustMixin


class SASVerificationSendDeviceNegotiationMixin(
    SASVerificationSendDeviceNegotiationMethodsMixin,
    SASVerificationSendDeviceNegotiationTrustMixin,
    SASVerificationSendDeviceNegotiationKeysMixin,
    SASVerificationSendDeviceNegotiationAlgorithmsMixin,
):
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    SASVerificationSendDeviceNegotiationMethodsMixin,
    SASVerificationSendDeviceNegotiationTrustMixin,
    SASVerificationSendDeviceNegotiationKeysMixin,
    SASVerificationSendDeviceNegotiationAlgorithmsMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationSendDeviceNegotiationMixin, _name, _method)

__all__ = ["SASVerificationSendDeviceNegotiationMixin"]
