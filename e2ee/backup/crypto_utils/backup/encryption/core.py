"""Matrix key-backup encryption orchestrator."""

from ... import (
    CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE,
)
from ... import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from ...compat import crypto_available, vodozemac_pk_available
from .crypto import _encrypt_backup_data_cryptography
from .guard import _validate_backup_public_key
from .vodozemac import _encrypt_backup_data_vodozemac


def _encrypt_backup_data(
    backup_public_key: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    按 Matrix Key Backup v1 规范加密备份数据。

    Returns:
        (ephemeral_public_key, ciphertext, mac)
    """
    _validate_backup_public_key(backup_public_key)

    if vodozemac_pk_available(_DEFAULT_VODOZEMAC_PK_AVAILABLE):
        return _encrypt_backup_data_vodozemac(backup_public_key, plaintext)

    if not crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        raise RuntimeError("需要 cryptography 或 vodozemac 库来加密密钥备份")

    return _encrypt_backup_data_cryptography(backup_public_key, plaintext)


__all__ = ["_encrypt_backup_data"]
