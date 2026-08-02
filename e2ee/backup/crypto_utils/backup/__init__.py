"""Composable Matrix key-backup encryption and decryption helpers."""

import base64
import hashlib
import hmac

from astrbot.api import logger

from .. import (
    AES_BLOCK_SIZE_16,
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
)
from .. import (
    CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE,
)
from .. import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from .. import (
    Curve25519PublicKey as _DEFAULT_CURVE25519_PUBLIC_KEY,
)
from .. import (
    PkEncryption as _DEFAULT_PK_ENCRYPTION,
)
from .. import (
    default_backend as _DEFAULT_DEFAULT_BACKEND,
)
from ..compat import crypto_available, resolve_attribute, vodozemac_pk_available
from .decryption import _decrypt_backup_data
from .encryption import _encrypt_backup_data
from .manual import _manual_decrypt_v1

__all__ = [
    "AES_BLOCK_SIZE_16",
    "CRYPTO_KEY_SIZE_32",
    "HKDF_KEY_MATERIAL_LEN",
    "HKDF_MEGOLM_BACKUP_INFO",
    "MAC_TRUNCATED_BYTES_8",
    "_DEFAULT_CRYPTO_AVAILABLE",
    "_DEFAULT_VODOZEMAC_PK_AVAILABLE",
    "_DEFAULT_CURVE25519_PUBLIC_KEY",
    "_DEFAULT_PK_ENCRYPTION",
    "_DEFAULT_DEFAULT_BACKEND",
    "_decrypt_backup_data",
    "_encrypt_backup_data",
    "_manual_decrypt_v1",
    "base64",
    "crypto_available",
    "hashlib",
    "hmac",
    "logger",
    "resolve_attribute",
    "vodozemac_pk_available",
]
