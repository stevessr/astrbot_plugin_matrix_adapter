"""Composable in-room SAS ready, start, accept, and key operations."""

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
)
from ...constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)
from ...crypto_utils import _canonical_json
from .accept import SASVerificationSendRoomAcceptMixin
from .compat import _vodozemac_sas_available
from .key import SASVerificationSendRoomKeyMixin
from .ready import SASVerificationSendRoomReadyMixin
from .start import SASVerificationSendRoomStartMixin


class SASVerificationSendRoomHandshakeMixin(
    SASVerificationSendRoomReadyMixin,
    SASVerificationSendRoomStartMixin,
    SASVerificationSendRoomAcceptMixin,
    SASVerificationSendRoomKeyMixin,
):
    """发送房间内 ready、start、accept 和 key 握手消息。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
SASVerificationSendRoomHandshakeMixin._send_in_room_ready = (
    SASVerificationSendRoomReadyMixin._send_in_room_ready
)
SASVerificationSendRoomHandshakeMixin._send_in_room_start = (
    SASVerificationSendRoomStartMixin._send_in_room_start
)
SASVerificationSendRoomHandshakeMixin._send_in_room_accept = (
    SASVerificationSendRoomAcceptMixin._send_in_room_accept
)
SASVerificationSendRoomHandshakeMixin._send_in_room_key = (
    SASVerificationSendRoomKeyMixin._send_in_room_key
)


__all__ = [
    "HASHES",
    "KEY_AGREEMENT_PROTOCOLS",
    "M_KEY_VERIFICATION_ACCEPT",
    "M_KEY_VERIFICATION_KEY",
    "M_KEY_VERIFICATION_READY",
    "M_KEY_VERIFICATION_START",
    "MESSAGE_AUTHENTICATION_CODES",
    "SASVerificationSendRoomAcceptMixin",
    "SASVerificationSendRoomHandshakeMixin",
    "SASVerificationSendRoomKeyMixin",
    "SASVerificationSendRoomReadyMixin",
    "SASVerificationSendRoomStartMixin",
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
