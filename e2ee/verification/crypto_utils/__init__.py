"""Composable canonical JSON, base64, and KDF helpers for verification."""

import base64
import hashlib
import hmac
import json

from .canonical import _canonical_json
from .encoding import _decode_base64, _encode_unpadded_base64
from .kdf import (
    SAS_MAC_LEGACY,
    SAS_MAC_V2,
    _calculate_sas_mac,
    _compute_hkdf,
    _compute_sas_mac_v2,
)

__all__ = [
    "SAS_MAC_LEGACY",
    "SAS_MAC_V2",
    "_calculate_sas_mac",
    "_canonical_json",
    "_compute_hkdf",
    "_compute_sas_mac_v2",
    "_decode_base64",
    "_encode_unpadded_base64",
    "base64",
    "hashlib",
    "hmac",
    "json",
]
