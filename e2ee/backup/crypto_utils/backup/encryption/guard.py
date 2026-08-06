"""Backup public key validation."""

from ... import CRYPTO_KEY_SIZE_32


def _validate_backup_public_key(backup_public_key: bytes) -> None:
    """Validate backup public key length."""
    if len(backup_public_key) != CRYPTO_KEY_SIZE_32:
        raise ValueError(
            f"备份公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(backup_public_key)} 字节"
        )


__all__ = ["_validate_backup_public_key"]
