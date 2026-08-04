"""Self-verification QR code generation."""

from .payload import SASVerificationFlowQRPayloadMixin
from .prepare import SASVerificationFlowQRPrepareMixin


class SASVerificationFlowQRMixin(
    SASVerificationFlowQRPayloadMixin,
    SASVerificationFlowQRPrepareMixin,
):
    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (
    SASVerificationFlowQRPayloadMixin,
    SASVerificationFlowQRPrepareMixin,
):
    for _name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(SASVerificationFlowQRMixin, _name, _method)

__all__ = ["SASVerificationFlowQRMixin"]
