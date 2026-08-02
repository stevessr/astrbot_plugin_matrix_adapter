"""Composable Secret Storage context mixins."""

import secrets

from astrbot.api import logger

from .....constants import CRYPTO_KEY_SIZE_32, SSSS_DEFAULT_KEY, SSSS_KEY_PREFIX
from ....verification.crypto_utils import _decode_base64
from .account import KeyBackupSSSSStorageContextAccountMixin
from .resolution import KeyBackupSSSSStorageContextResolutionMixin
from .validation import KeyBackupSSSSStorageContextValidationMixin


class KeyBackupSSSSStorageContextMixin(
    KeyBackupSSSSStorageContextValidationMixin,
    KeyBackupSSSSStorageContextResolutionMixin,
    KeyBackupSSSSStorageContextAccountMixin,
):
    """验证 Secret Storage key 并构建可用的加密上下文。"""

    pass


KeyBackupSSSSStorageContextMixin._secret_storage_key_matches = (
    KeyBackupSSSSStorageContextValidationMixin.__dict__["_secret_storage_key_matches"]
)
KeyBackupSSSSStorageContextMixin._resolve_secret_storage_key = (
    KeyBackupSSSSStorageContextResolutionMixin.__dict__["_resolve_secret_storage_key"]
)
KeyBackupSSSSStorageContextMixin._resolve_secret_storage_context = (
    KeyBackupSSSSStorageContextResolutionMixin.__dict__[
        "_resolve_secret_storage_context"
    ]
)
KeyBackupSSSSStorageContextMixin._build_secret_storage_key_account_data = (
    KeyBackupSSSSStorageContextAccountMixin.__dict__[
        "_build_secret_storage_key_account_data"
    ]
)


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupSSSSStorageContextAccountMixin",
    "KeyBackupSSSSStorageContextMixin",
    "KeyBackupSSSSStorageContextResolutionMixin",
    "KeyBackupSSSSStorageContextValidationMixin",
    "SSSS_DEFAULT_KEY",
    "SSSS_KEY_PREFIX",
    "_decode_base64",
    "logger",
    "secrets",
]
