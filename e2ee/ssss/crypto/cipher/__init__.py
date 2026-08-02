"""Composable Secret Storage AES-CTR/HMAC cipher mixins."""

import secrets

from astrbot.api import logger

from .....constants import CRYPTO_KEY_SIZE_32
from ....backup.crypto_utils import _aes_ctr_decrypt, _compute_hkdf
from ....verification.crypto_utils import _decode_base64, _encode_unpadded_base64
from ..compat import _DEFAULT_CRYPTO_AVAILABLE, crypto_available
from .decryption import KeyBackupSSSSCipherDecryptionMixin
from .encryption import KeyBackupSSSSCipherEncryptionMixin


class KeyBackupSSSSCipherMixin(
    KeyBackupSSSSCipherEncryptionMixin,
    KeyBackupSSSSCipherDecryptionMixin,
):
    """Matrix Secret Storage AES-CTR 与 HMAC-SHA-256 加解密。"""

    pass


KeyBackupSSSSCipherMixin._encrypt_ssss_data = (
    KeyBackupSSSSCipherEncryptionMixin.__dict__["_encrypt_ssss_data"]
)
KeyBackupSSSSCipherMixin._decrypt_ssss_data = (
    KeyBackupSSSSCipherDecryptionMixin.__dict__["_decrypt_ssss_data"]
)


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupSSSSCipherDecryptionMixin",
    "KeyBackupSSSSCipherEncryptionMixin",
    "KeyBackupSSSSCipherMixin",
    "_DEFAULT_CRYPTO_AVAILABLE",
    "_aes_ctr_decrypt",
    "_compute_hkdf",
    "_decode_base64",
    "_encode_unpadded_base64",
    "crypto_available",
    "logger",
    "secrets",
]
