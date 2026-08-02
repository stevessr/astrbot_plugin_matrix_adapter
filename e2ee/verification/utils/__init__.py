"""Composable masking, identity, QR, and SAS verification utilities."""

import base64
import hashlib
import secrets

from astrbot.api import logger

from ....constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    PREFIX_ED25519,
    QR_CODE_HEADER,
    QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
    QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER,
    QR_CODE_VERSION,
    SAS_BYTES_LENGTH_6,
)
from ..crypto_utils import _encode_unpadded_base64
from .identity import SASVerificationFlowIdentityMixin
from .masking import SASVerificationFlowMaskingMixin
from .qr import SASVerificationFlowQRMixin
from .sas import SASVerificationFlowSASMixin


class SASVerificationFlowUtilsMixin(
    SASVerificationFlowMaskingMixin,
    SASVerificationFlowIdentityMixin,
    SASVerificationFlowQRMixin,
    SASVerificationFlowSASMixin,
):
    """Verification helpers split by masking, identity, QR, and SAS concerns."""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
SASVerificationFlowUtilsMixin._mask_identifier = staticmethod(
    SASVerificationFlowMaskingMixin._mask_identifier
)
SASVerificationFlowUtilsMixin._mask_txn_id = staticmethod(
    SASVerificationFlowMaskingMixin._mask_txn_id
)
SASVerificationFlowUtilsMixin._supports_method = staticmethod(
    SASVerificationFlowMaskingMixin._supports_method
)
SASVerificationFlowUtilsMixin._decode_unpadded_base64 = staticmethod(
    SASVerificationFlowMaskingMixin._decode_unpadded_base64
)
SASVerificationFlowUtilsMixin._get_local_device_ed25519_key = (
    SASVerificationFlowIdentityMixin._get_local_device_ed25519_key
)
SASVerificationFlowUtilsMixin._device_trusts_master_key = staticmethod(
    SASVerificationFlowIdentityMixin._device_trusts_master_key
)
SASVerificationFlowUtilsMixin._can_continue_with_qr = (
    SASVerificationFlowIdentityMixin._can_continue_with_qr
)
SASVerificationFlowUtilsMixin._build_self_verification_qr_payload = (
    SASVerificationFlowQRMixin._build_self_verification_qr_payload
)
SASVerificationFlowUtilsMixin._maybe_prepare_self_verification_qr = (
    SASVerificationFlowQRMixin._maybe_prepare_self_verification_qr
)
SASVerificationFlowUtilsMixin._compute_sas_fallback = (
    SASVerificationFlowSASMixin._compute_sas_fallback
)


__all__ = [
    "M_QR_CODE_SCAN_V1_METHOD",
    "M_QR_CODE_SHOW_V1_METHOD",
    "M_RECIPROCATE_V1_METHOD",
    "PREFIX_ED25519",
    "QR_CODE_HEADER",
    "QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER",
    "QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER",
    "QR_CODE_VERSION",
    "SASVerificationFlowIdentityMixin",
    "SASVerificationFlowMaskingMixin",
    "SASVerificationFlowQRMixin",
    "SASVerificationFlowSASMixin",
    "SASVerificationFlowUtilsMixin",
    "SAS_BYTES_LENGTH_6",
    "_encode_unpadded_base64",
    "base64",
    "hashlib",
    "logger",
    "secrets",
]
