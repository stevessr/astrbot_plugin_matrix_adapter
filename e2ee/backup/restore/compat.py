"""Compatibility helpers for patchable restore-module dependencies."""

import sys

from ..crypto_utils import (
    VODOZEMAC_PK_AVAILABLE as _DEFAULT_VODOZEMAC_PK_AVAILABLE,
)
from ..crypto_utils import (
    Curve25519SecretKey as _DEFAULT_CURVE25519_SECRET_KEY,
)
from ..crypto_utils import (
    PkDecryption as _DEFAULT_PK_DECRYPTION,
)
from ..crypto_utils import (
    _decode_recovery_key as _DEFAULT_DECODE_RECOVERY_KEY,
)
from ..crypto_utils import (
    _decrypt_backup_data as _DEFAULT_DECRYPT_BACKUP_DATA,
)


def resolve_restore_symbol(name: str, default):
    """Resolve a dependency from the compatibility package namespace."""
    package = sys.modules.get(__package__)
    return getattr(package, name, default) if package is not None else default


__all__ = [
    "_DEFAULT_CURVE25519_SECRET_KEY",
    "_DEFAULT_DECODE_RECOVERY_KEY",
    "_DEFAULT_DECRYPT_BACKUP_DATA",
    "_DEFAULT_PK_DECRYPTION",
    "_DEFAULT_VODOZEMAC_PK_AVAILABLE",
    "resolve_restore_symbol",
]
