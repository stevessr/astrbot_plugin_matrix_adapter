"""Composable in-room SAS MAC, done, and cancel operations."""

import base64
import hashlib
import sys

from astrbot.api import logger

from .....constants import (
    INFO_PREFIX_MAC,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_MAC,
)
from ...constants import VODOZEMAC_SAS_AVAILABLE
from ...crypto_utils import _compute_hkdf
from .cancel import SASVerificationSendRoomCancelMixin
from .compat import _vodozemac_sas_available
from .done import SASVerificationSendRoomDoneMixin
from .mac import SASVerificationSendRoomMACMixin


class SASVerificationSendRoomMessagesMixin(
    SASVerificationSendRoomMACMixin,
    SASVerificationSendRoomDoneMixin,
    SASVerificationSendRoomCancelMixin,
):
    """发送房间内 MAC、done 和 cancel 消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
SASVerificationSendRoomMessagesMixin._send_in_room_mac = (
    SASVerificationSendRoomMACMixin._send_in_room_mac
)
SASVerificationSendRoomMessagesMixin._send_in_room_done = (
    SASVerificationSendRoomDoneMixin._send_in_room_done
)
SASVerificationSendRoomMessagesMixin._send_in_room_cancel = (
    SASVerificationSendRoomCancelMixin._send_in_room_cancel
)


__all__ = [
    "INFO_PREFIX_MAC",
    "M_KEY_VERIFICATION_CANCEL",
    "M_KEY_VERIFICATION_DONE",
    "M_KEY_VERIFICATION_MAC",
    "SASVerificationSendRoomCancelMixin",
    "SASVerificationSendRoomDoneMixin",
    "SASVerificationSendRoomMACMixin",
    "SASVerificationSendRoomMessagesMixin",
    "VODOZEMAC_SAS_AVAILABLE",
    "_compute_hkdf",
    "_vodozemac_sas_available",
    "base64",
    "hashlib",
    "logger",
    "sys",
]
