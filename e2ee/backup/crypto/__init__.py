"""Composable Matrix key-backup cryptography operations."""

import base64
import hashlib
import hmac

from astrbot.api import logger

from ....constants import (
    AES_GCM_NONCE_LEN,
    CRYPTO_KEY_SIZE_32,
    MEGOLM_ALGO,
    RECOVERY_KEY_MAC_TRUNCATED_LEN,
)
from ...megolm.inbound import _convert_session_key_v2_to_v1
from ..crypto_utils import (
    _aes_decrypt,
    _aes_encrypt,
    _encrypt_backup_data,
)
from .encoding import KeyBackupCryptoEncodingMixin
from .recovery import KeyBackupCryptoRecoveryMixin
from .session import KeyBackupCryptoSessionMixin


class KeyBackupBackupCryptoMixin(
    KeyBackupCryptoEncodingMixin,
    KeyBackupCryptoSessionMixin,
    KeyBackupCryptoRecoveryMixin,
):
    """分层处理备份编码、会话加密与恢复密钥验证。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
KeyBackupBackupCryptoMixin._decode_unpadded_base64 = staticmethod(
    KeyBackupCryptoEncodingMixin.__dict__["_decode_unpadded_base64"].__func__
)
KeyBackupBackupCryptoMixin._get_backup_public_key_bytes = (
    KeyBackupCryptoEncodingMixin._get_backup_public_key_bytes
)

KeyBackupBackupCryptoMixin._build_encrypted_session_data = (
    KeyBackupCryptoSessionMixin._build_encrypted_session_data
)
KeyBackupBackupCryptoMixin._build_backed_up_session_data = staticmethod(
    KeyBackupCryptoSessionMixin.__dict__["_build_backed_up_session_data"].__func__
)
KeyBackupBackupCryptoMixin._decrypt_legacy_backup_data = (
    KeyBackupCryptoSessionMixin._decrypt_legacy_backup_data
)
KeyBackupBackupCryptoMixin._verify_recovery_key = (
    KeyBackupCryptoRecoveryMixin._verify_recovery_key
)


__all__ = [
    "AES_GCM_NONCE_LEN",
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupBackupCryptoMixin",
    "KeyBackupCryptoEncodingMixin",
    "KeyBackupCryptoRecoveryMixin",
    "KeyBackupCryptoSessionMixin",
    "MEGOLM_ALGO",
    "RECOVERY_KEY_MAC_TRUNCATED_LEN",
    "_aes_decrypt",
    "_aes_encrypt",
    "_convert_session_key_v2_to_v1",
    "_encrypt_backup_data",
    "base64",
    "hashlib",
    "hmac",
    "logger",
]
