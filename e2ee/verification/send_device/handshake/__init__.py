"""Composable SAS ready/start, accept, and key message operations."""

import base64
import hashlib
import secrets
import sys

from astrbot.api import logger

from .....constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_START,
    M_SAS_V1_METHOD,
)
from ...constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)
from ...crypto_utils import _canonical_json
from .compat import _vodozemac_sas_available
from .key import SASVerificationHandshakeKeyMixin
from .messages import SASVerificationHandshakeMessagesMixin
from .negotiation import SASVerificationHandshakeNegotiationMixin


class SASVerificationSendDeviceHandshakeMixin(
    SASVerificationHandshakeMessagesMixin,
    SASVerificationHandshakeNegotiationMixin,
    SASVerificationHandshakeKeyMixin,
):
    """发送 SAS ready、start、accept 和 key 握手消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
SASVerificationSendDeviceHandshakeMixin._send_ready = (
    SASVerificationHandshakeMessagesMixin._send_ready
)
SASVerificationSendDeviceHandshakeMixin._send_start = (
    SASVerificationHandshakeMessagesMixin._send_start
)
SASVerificationSendDeviceHandshakeMixin._send_accept = (
    SASVerificationHandshakeNegotiationMixin._send_accept
)
SASVerificationSendDeviceHandshakeMixin._send_key = (
    SASVerificationHandshakeKeyMixin._send_key
)


__all__ = [
    "HASHES",
    "KEY_AGREEMENT_PROTOCOLS",
    "M_KEY_VERIFICATION_ACCEPT",
    "M_KEY_VERIFICATION_KEY",
    "M_KEY_VERIFICATION_READY",
    "M_KEY_VERIFICATION_START",
    "M_SAS_V1_METHOD",
    "MESSAGE_AUTHENTICATION_CODES",
    "SASVerificationHandshakeKeyMixin",
    "SASVerificationHandshakeMessagesMixin",
    "SASVerificationHandshakeNegotiationMixin",
    "SASVerificationSendDeviceHandshakeMixin",
    "SHORT_AUTHENTICATION_STRING",
    "Sas",
    "VODOZEMAC_SAS_AVAILABLE",
    "_canonical_json",
    "_vodozemac_sas_available",
    "base64",
    "hashlib",
    "logger",
    "secrets",
    "sys",
]
