"""SAS accept negotiation and commitment construction."""

from .core import SASVerificationHandshakeNegotiationCoreMixin
from .key import SASVerificationHandshakeNegotiationKeyMixin


class SASVerificationHandshakeNegotiationMixin(
    SASVerificationHandshakeNegotiationCoreMixin,
    SASVerificationHandshakeNegotiationKeyMixin,
):
    """协商 SAS 算法并构造 accept 消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    SASVerificationHandshakeNegotiationCoreMixin,
    SASVerificationHandshakeNegotiationKeyMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationHandshakeNegotiationMixin, _name, _method)

__all__ = ["SASVerificationHandshakeNegotiationMixin"]
