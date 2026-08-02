"""Composable manual verification notification helpers."""

from __future__ import annotations

from astrbot.api import logger

from ....constants import M_ROOM_MESSAGE
from ....sender.events.common import send_content
from .masking import SASVerificationManualNotifyMaskingMixin
from .rooms import SASVerificationManualNotifyRoomsMixin
from .sending import SASVerificationManualNotifySendingMixin


class SASVerificationManualNotifyMixin(
    SASVerificationManualNotifyMaskingMixin,
    SASVerificationManualNotifyRoomsMixin,
    SASVerificationManualNotifySendingMixin,
):
    """Manual verification notification helpers split by responsibility."""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
SASVerificationManualNotifyMixin._mask_txn_id = staticmethod(
    SASVerificationManualNotifyMaskingMixin._mask_txn_id
)
SASVerificationManualNotifyMixin.set_admin_notify_rooms = (
    SASVerificationManualNotifyRoomsMixin.set_admin_notify_rooms
)
SASVerificationManualNotifyMixin.get_admin_notify_rooms = (
    SASVerificationManualNotifyRoomsMixin.get_admin_notify_rooms
)
SASVerificationManualNotifyMixin._send_manual_verification_notice = (
    SASVerificationManualNotifySendingMixin._send_manual_verification_notice
)
SASVerificationManualNotifyMixin._notify_admin_rooms_for_verification = (
    SASVerificationManualNotifySendingMixin._notify_admin_rooms_for_verification
)


__all__ = [
    "M_ROOM_MESSAGE",
    "SASVerificationManualNotifyMaskingMixin",
    "SASVerificationManualNotifyMixin",
    "SASVerificationManualNotifyRoomsMixin",
    "SASVerificationManualNotifySendingMixin",
    "logger",
    "send_content",
]
