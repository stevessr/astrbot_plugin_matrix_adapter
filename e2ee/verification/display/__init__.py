"""Composable QR, notification, approval, and SAS display helpers."""

import io

from astrbot.api import logger

from ....constants import (
    SAS_BYTES_LENGTH_6,
    SAS_EMOJI_COUNT_7,
)
from ..constants import SAS_EMOJIS
from .approval import SASVerificationDisplayApprovalMixin
from .notifications import SASVerificationDisplayNotificationsMixin
from .qr import SASVerificationDisplayQRMixin
from .sas import SASVerificationDisplaySASMixin


class SASVerificationDisplayMixin(
    SASVerificationDisplayQRMixin,
    SASVerificationDisplayNotificationsMixin,
    SASVerificationDisplayApprovalMixin,
    SASVerificationDisplaySASMixin,
):
    """Verification display helpers split by output responsibility."""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
SASVerificationDisplayMixin._build_terminal_qr = staticmethod(
    SASVerificationDisplayQRMixin._build_terminal_qr
)
SASVerificationDisplayMixin._notify_admin_for_verification = (
    SASVerificationDisplayNotificationsMixin._notify_admin_for_verification
)
SASVerificationDisplayMixin._notify_admin_for_qr_code = (
    SASVerificationDisplayNotificationsMixin._notify_admin_for_qr_code
)
SASVerificationDisplayMixin._notify_admin_for_qr_reciprocation = (
    SASVerificationDisplayNotificationsMixin._notify_admin_for_qr_reciprocation
)
SASVerificationDisplayMixin._notify_admin_to_scan_peer_qr = (
    SASVerificationDisplayNotificationsMixin._notify_admin_to_scan_peer_qr
)
SASVerificationDisplayMixin._notify_user_for_approval = (
    SASVerificationDisplayApprovalMixin._notify_user_for_approval
)
SASVerificationDisplayMixin._bytes_to_emoji = (
    SASVerificationDisplaySASMixin._bytes_to_emoji
)
SASVerificationDisplayMixin._bytes_to_decimal = (
    SASVerificationDisplaySASMixin._bytes_to_decimal
)


__all__ = [
    "SASVerificationDisplayApprovalMixin",
    "SASVerificationDisplayMixin",
    "SASVerificationDisplayNotificationsMixin",
    "SASVerificationDisplayQRMixin",
    "SASVerificationDisplaySASMixin",
    "SAS_BYTES_LENGTH_6",
    "SAS_EMOJI_COUNT_7",
    "SAS_EMOJIS",
    "io",
    "logger",
]
