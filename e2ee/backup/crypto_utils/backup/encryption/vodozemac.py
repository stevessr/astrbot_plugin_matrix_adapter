"""Vodozemac-backed key-backup encryption."""

import base64

from ... import (
    Curve25519PublicKey as _DEFAULT_CURVE25519_PUBLIC_KEY,
)
from ... import (
    PkEncryption as _DEFAULT_PK_ENCRYPTION,
)
from ...compat import resolve_attribute


def _encrypt_backup_data_vodozemac(
    backup_public_key: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt backup data with vodozemac; return (ephemeral, ciphertext, mac)."""
    public_key_cls = resolve_attribute(
        "Curve25519PublicKey",
        _DEFAULT_CURVE25519_PUBLIC_KEY,
    )
    pk_encryption_cls = resolve_attribute(
        "PkEncryption",
        _DEFAULT_PK_ENCRYPTION,
    )
    public_key = public_key_cls.from_base64(
        base64.b64encode(backup_public_key).decode()
    )
    message = pk_encryption_cls.from_key(public_key).encrypt(plaintext)
    return message.ephemeral_key, message.ciphertext, message.mac


__all__ = ["_encrypt_backup_data_vodozemac"]
