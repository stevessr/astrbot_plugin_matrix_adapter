"""Composable QR payload, session, and scan operations."""

import base64
from pathlib import Path
from typing import Any

from astrbot.api import logger

from .....constants import (
    M_KEY_VERIFICATION_START,
    M_RECIPROCATE_V1_METHOD,
    PREFIX_ED25519,
    QR_CODE_HEADER,
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
    QR_CODE_VERSION,
)
from ...crypto_utils import _encode_unpadded_base64
from .decoding import SASVerificationQRDecodingMixin
from .scanning import SASVerificationQRScanningMixin
from .sessions import SASVerificationQRSessionMixin


class SASVerificationQRMixin(
    SASVerificationQRDecodingMixin,
    SASVerificationQRSessionMixin,
    SASVerificationQRScanningMixin,
):
    """二维码载荷解析、会话匹配和 reciprocate 发送。"""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
SASVerificationQRMixin._decode_base64_payload = staticmethod(
    SASVerificationQRDecodingMixin._decode_base64_payload
)
SASVerificationQRMixin._decode_qr_image = staticmethod(
    SASVerificationQRDecodingMixin._decode_qr_image
)
SASVerificationQRMixin._parse_verification_qr_payload = staticmethod(
    SASVerificationQRDecodingMixin._parse_verification_qr_payload
)
SASVerificationQRMixin._load_qr_payload_bytes = (
    SASVerificationQRDecodingMixin._load_qr_payload_bytes
)
SASVerificationQRMixin._find_session_for_qr_scan = (
    SASVerificationQRSessionMixin._find_session_for_qr_scan
)
SASVerificationQRMixin.scan_qr = SASVerificationQRScanningMixin.scan_qr


__all__ = [
    "Any",
    "M_KEY_VERIFICATION_START",
    "M_RECIPROCATE_V1_METHOD",
    "Path",
    "PREFIX_ED25519",
    "QR_CODE_HEADER",
    "QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER",
    "QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER",
    "QR_CODE_VERSION",
    "SASVerificationQRDecodingMixin",
    "SASVerificationQRMixin",
    "SASVerificationQRScanningMixin",
    "SASVerificationQRSessionMixin",
    "_encode_unpadded_base64",
    "base64",
    "logger",
]
