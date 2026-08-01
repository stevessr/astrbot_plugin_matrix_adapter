"""Compatibility exports for the split cross-signing implementation."""

from ..client.http_client import MatrixAPIError
from .constants import (
    DEVICE_SECRET_REQUEST_FAILED,
    DEVICE_SECRET_REQUEST_NOT_NEEDED,
    DEVICE_SECRET_REQUEST_PENDING,
    DEVICE_SECRET_REQUEST_UNAVAILABLE,
    FORCE_OVERWRITE_SERVER_KEYS,
)
from .key_backup_crypto import CRYPTO_AVAILABLE
from .signing import CrossSigning

__all__ = [
    "CrossSigning",
    "CRYPTO_AVAILABLE",
    "DEVICE_SECRET_REQUEST_FAILED",
    "DEVICE_SECRET_REQUEST_NOT_NEEDED",
    "DEVICE_SECRET_REQUEST_PENDING",
    "DEVICE_SECRET_REQUEST_UNAVAILABLE",
    "FORCE_OVERWRITE_SERVER_KEYS",
    "MatrixAPIError",
]
