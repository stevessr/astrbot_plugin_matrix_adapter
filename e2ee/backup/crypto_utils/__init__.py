"""Composable Matrix backup cryptography utilities."""

import base64
import hashlib
import hmac
import secrets

from astrbot.api import logger

from ....constants import (
    AES_BLOCK_SIZE_16,
    AES_GCM_NONCE_LEN,
    BASE58_ALPHABET,
    CRYPTO_KEY_SIZE_32,
    HKDF_KEY_MATERIAL_LEN,
    HKDF_MEGOLM_BACKUP_INFO,
    MAC_TRUNCATED_BYTES_8,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
)

# 尝试导入加密库
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTO_AVAILABLE = True
except ImportError:
    default_backend = None
    hashes = None
    crypto_hmac = None
    AESGCM = None
    HKDF = None
    CRYPTO_AVAILABLE = False
    logger.debug("cryptography 库不可用，密钥备份将使用简化加密")

# 尝试导入 vodozemac (用于 Matrix 兼容的 PkDecryption)
try:
    from vodozemac import (
        Curve25519PublicKey,
        Curve25519SecretKey,
        PkDecodeException,
        PkDecryption,
        PkEncryption,
    )

    VODOZEMAC_PK_AVAILABLE = True
except ImportError:
    VODOZEMAC_PK_AVAILABLE = False
    Curve25519PublicKey = None
    Curve25519SecretKey = None
    PkDecryption = None
    PkEncryption = None
    PkDecodeException = Exception  # 回退到通用异常
    logger.debug("vodozemac PkDecryption 不可用")

from .backup import _decrypt_backup_data, _encrypt_backup_data, _manual_decrypt_v1
from .kdf import _compute_hkdf
from .recovery import _decode_recovery_key, _encode_recovery_key
from .symmetric import _aes_ctr_decrypt, _aes_decrypt, _aes_encrypt

__all__ = [
    "AESGCM",
    "AES_BLOCK_SIZE_16",
    "AES_GCM_NONCE_LEN",
    "BASE58_ALPHABET",
    "CRYPTO_AVAILABLE",
    "CRYPTO_KEY_SIZE_32",
    "Curve25519PublicKey",
    "Curve25519SecretKey",
    "HKDF",
    "HKDF_KEY_MATERIAL_LEN",
    "HKDF_MEGOLM_BACKUP_INFO",
    "MAC_TRUNCATED_BYTES_8",
    "PkDecodeException",
    "PkDecryption",
    "PkEncryption",
    "RECOVERY_KEY_HDR_BYTE1",
    "RECOVERY_KEY_HDR_BYTE2",
    "RECOVERY_KEY_PRIV_LEN",
    "RECOVERY_KEY_TOTAL_LEN",
    "VODOZEMAC_PK_AVAILABLE",
    "_aes_ctr_decrypt",
    "_aes_decrypt",
    "_aes_encrypt",
    "_compute_hkdf",
    "_decode_recovery_key",
    "_decrypt_backup_data",
    "_encode_recovery_key",
    "_encrypt_backup_data",
    "_manual_decrypt_v1",
    "base64",
    "crypto_hmac",
    "default_backend",
    "hashlib",
    "hashes",
    "hmac",
    "logger",
    "secrets",
]
