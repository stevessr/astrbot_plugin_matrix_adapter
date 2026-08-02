"""Composable SAS verification manager package."""

from .approval import SASVerificationApprovalMixin
from .core import SASVerification
from .qr import SASVerificationQRMixin

# Preserve direct class attributes exposed by the former monolithic module.
for _method_name in (
    "_load_qr_payload_bytes",
    "_find_session_for_qr_scan",
    "scan_qr",
):
    setattr(
        SASVerification, _method_name, getattr(SASVerificationQRMixin, _method_name)
    )

for _method_name in (
    "_decode_base64_payload",
    "_decode_qr_image",
    "_parse_verification_qr_payload",
):
    setattr(
        SASVerification,
        _method_name,
        staticmethod(getattr(SASVerificationQRMixin, _method_name)),
    )

SASVerification.approve_device = SASVerificationApprovalMixin.approve_device

__all__ = [
    "SASVerification",
    "SASVerificationApprovalMixin",
    "SASVerificationQRMixin",
]
