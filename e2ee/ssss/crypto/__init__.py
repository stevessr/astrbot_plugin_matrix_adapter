"""Composable Secret Storage input/output and crypto operations."""

import secrets

from astrbot.api import logger

from ....constants import CRYPTO_KEY_SIZE_32, SSSS_BACKUP_SECRET
from ...backup.crypto_utils import (
    CRYPTO_AVAILABLE,
    _aes_ctr_decrypt,
    _compute_hkdf,
    _decode_recovery_key,
)
from ...verification.crypto_utils import _decode_base64, _encode_unpadded_base64
from .cipher import KeyBackupSSSSCipherMixin
from .compat import _DEFAULT_CRYPTO_AVAILABLE, crypto_available, resolve_ssss_symbol
from .io import KeyBackupSSSSStorageIOMixin


class KeyBackupSSSSMixinCrypto(
    KeyBackupSSSSStorageIOMixin,
    KeyBackupSSSSCipherMixin,
):
    """Secret Storage 秘密读写、恢复与加解密 Mixin。"""

    pass


# Preserve direct method attributes exposed by the former monolithic mixin.
KeyBackupSSSSMixinCrypto.read_secret_from_secret_storage = (
    KeyBackupSSSSStorageIOMixin.read_secret_from_secret_storage
)
KeyBackupSSSSMixinCrypto.write_secret_to_secret_storage = (
    KeyBackupSSSSStorageIOMixin.write_secret_to_secret_storage
)
KeyBackupSSSSMixinCrypto._try_restore_from_secret_storage = (
    KeyBackupSSSSStorageIOMixin._try_restore_from_secret_storage
)
KeyBackupSSSSMixinCrypto._encrypt_ssss_data = (
    KeyBackupSSSSCipherMixin._encrypt_ssss_data
)
KeyBackupSSSSMixinCrypto._decrypt_ssss_data = (
    KeyBackupSSSSCipherMixin._decrypt_ssss_data
)


__all__ = [
    "CRYPTO_AVAILABLE",
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupSSSSCipherMixin",
    "KeyBackupSSSSMixinCrypto",
    "KeyBackupSSSSStorageIOMixin",
    "SSSS_BACKUP_SECRET",
    "_DEFAULT_CRYPTO_AVAILABLE",
    "_aes_ctr_decrypt",
    "_compute_hkdf",
    "_decode_base64",
    "_decode_recovery_key",
    "_encode_unpadded_base64",
    "crypto_available",
    "logger",
    "resolve_ssss_symbol",
    "secrets",
]
