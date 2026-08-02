"""Composable manual and QR verification notification helpers."""

from astrbot.api import logger

from .manual import SASVerificationDisplayManualNotificationMixin
from .qr import SASVerificationDisplayQRNotificationMixin
from .reciprocation import SASVerificationDisplayQRReciprocationNotificationMixin


class SASVerificationDisplayNotificationsMixin(
    SASVerificationDisplayManualNotificationMixin,
    SASVerificationDisplayQRNotificationMixin,
    SASVerificationDisplayQRReciprocationNotificationMixin,
):
    """Verification notifications split by manual and QR responsibilities."""

    pass


# Preserve direct method attributes exposed by the former mixin.
SASVerificationDisplayNotificationsMixin._notify_admin_for_verification = (
    SASVerificationDisplayManualNotificationMixin.__dict__[
        "_notify_admin_for_verification"
    ]
)
SASVerificationDisplayNotificationsMixin._notify_admin_for_qr_code = (
    SASVerificationDisplayQRNotificationMixin.__dict__["_notify_admin_for_qr_code"]
)
SASVerificationDisplayNotificationsMixin._notify_admin_for_qr_reciprocation = (
    SASVerificationDisplayQRReciprocationNotificationMixin.__dict__[  # noqa: E501
        "_notify_admin_for_qr_reciprocation"
    ]
)
SASVerificationDisplayNotificationsMixin._notify_admin_to_scan_peer_qr = (
    SASVerificationDisplayQRReciprocationNotificationMixin.__dict__[
        "_notify_admin_to_scan_peer_qr"
    ]
)


__all__ = [
    "SASVerificationDisplayManualNotificationMixin",
    "SASVerificationDisplayNotificationsMixin",
    "SASVerificationDisplayQRNotificationMixin",
    "SASVerificationDisplayQRReciprocationNotificationMixin",
    "logger",
]
