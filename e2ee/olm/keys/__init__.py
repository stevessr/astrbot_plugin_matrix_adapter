"""Composable Olm identity, one-time-key, and verification operations."""

from typing import Any

from astrbot.api import logger

from ....constants import (
    DEFAULT_ONE_TIME_KEYS_COUNT,
    MEGOLM_ALGO,
    OLM_ALGO,
)
from ...verification.crypto_utils import _canonical_json
from ..types import Ed25519PublicKey, Ed25519Signature
from .identity import OlmMachineKeyIdentityMixin
from .one_time import OlmMachineOneTimeKeysMixin
from .verification import OlmMachineKeyVerificationMixin


class OlmMachineKeysMixin(
    OlmMachineKeyIdentityMixin,
    OlmMachineOneTimeKeysMixin,
    OlmMachineKeyVerificationMixin,
):
    """Olm 设备密钥生成、发布与验证 Mixin。"""

    pass


# Preserve direct method and descriptor attributes exposed by the former
# monolithic mixin.  Class methods and properties must retain their descriptors.
OlmMachineKeysMixin.get_identity_keys = OlmMachineKeyIdentityMixin.get_identity_keys
OlmMachineKeysMixin.get_device_keys = OlmMachineKeyIdentityMixin.get_device_keys
OlmMachineKeysMixin.generate_one_time_keys = (
    OlmMachineOneTimeKeysMixin.generate_one_time_keys
)
OlmMachineKeysMixin.mark_keys_as_published = (
    OlmMachineOneTimeKeysMixin.mark_keys_as_published
)
OlmMachineKeysMixin.generate_fallback_key = (
    OlmMachineOneTimeKeysMixin.generate_fallback_key
)
OlmMachineKeysMixin.get_unpublished_fallback_key_count = (
    OlmMachineOneTimeKeysMixin.get_unpublished_fallback_key_count
)
OlmMachineKeysMixin.verify_json_signature = OlmMachineKeyVerificationMixin.__dict__[
    "verify_json_signature"
]
OlmMachineKeysMixin.verify_device_keys = OlmMachineKeyVerificationMixin.__dict__[
    "verify_device_keys"
]
OlmMachineKeysMixin.select_verified_one_time_key = (
    OlmMachineKeyVerificationMixin.__dict__["select_verified_one_time_key"]
)
OlmMachineKeysMixin.curve25519_key = OlmMachineKeyIdentityMixin.__dict__[
    "curve25519_key"
]
OlmMachineKeysMixin.ed25519_key = OlmMachineKeyIdentityMixin.__dict__["ed25519_key"]


__all__ = [
    "Any",
    "DEFAULT_ONE_TIME_KEYS_COUNT",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "MEGOLM_ALGO",
    "OLM_ALGO",
    "OlmMachineKeyIdentityMixin",
    "OlmMachineKeyVerificationMixin",
    "OlmMachineKeysMixin",
    "OlmMachineOneTimeKeysMixin",
    "_canonical_json",
    "logger",
]
