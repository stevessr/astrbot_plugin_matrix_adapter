"""Composable verification MAC, control, and transport mixins."""

import base64
import hashlib
import secrets
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
from .compat import _vodozemac_sas_available
from .control import SASVerificationSendDeviceControlMixin
from .mac import SASVerificationSendDeviceMACMixin
from .transport import SASVerificationSendDeviceTransportMixin


class SASVerificationSendDeviceMessagesMixin(
    SASVerificationSendDeviceMACMixin,
    SASVerificationSendDeviceControlMixin,
    SASVerificationSendDeviceTransportMixin,
):
    """发送验证 MAC、done、cancel 以及底层 to-device 消息。"""

    pass


SASVerificationSendDeviceMessagesMixin._send_mac = (
    SASVerificationSendDeviceMACMixin.__dict__["_send_mac"]
)
SASVerificationSendDeviceMessagesMixin._send_done = (
    SASVerificationSendDeviceControlMixin.__dict__["_send_done"]
)
SASVerificationSendDeviceMessagesMixin._send_cancel = (
    SASVerificationSendDeviceControlMixin.__dict__["_send_cancel"]
)
SASVerificationSendDeviceMessagesMixin._send_to_device = (
    SASVerificationSendDeviceTransportMixin.__dict__["_send_to_device"]
)


__all__ = [
    "INFO_PREFIX_MAC",
    "M_KEY_VERIFICATION_CANCEL",
    "M_KEY_VERIFICATION_DONE",
    "M_KEY_VERIFICATION_MAC",
    "SASVerificationSendDeviceControlMixin",
    "SASVerificationSendDeviceMACMixin",
    "SASVerificationSendDeviceMessagesMixin",
    "SASVerificationSendDeviceTransportMixin",
    "VODOZEMAC_SAS_AVAILABLE",
    "_compute_hkdf",
    "_vodozemac_sas_available",
    "base64",
    "hashlib",
    "logger",
    "secrets",
    "sys",
]
