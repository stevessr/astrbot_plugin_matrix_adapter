"""Composable Secret Storage key and dehydrated-device helpers."""

import json
import secrets

from astrbot.api import logger

from ....constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from ...backup.crypto_utils import _decode_recovery_key
from ...verification.crypto_utils import _decode_base64
from .cache import KeyBackupSSSSStorageCacheMixin
from .context import KeyBackupSSSSStorageContextMixin
from .recovery import KeyBackupSSSSStorageRecoveryMixin


class KeyBackupSSSSStorageMixin(
    KeyBackupSSSSStorageRecoveryMixin,
    KeyBackupSSSSStorageCacheMixin,
    KeyBackupSSSSStorageContextMixin,
):
    """分层处理 Secret Storage key、恢复密钥和 dehydrated device。"""

    _SSSS_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
    _SSSS_BOOTSTRAP_KEY_NAME = "AstrBot Secret Storage"

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_get_valid_local_recovery_key_bytes",
    "_get_dehydrated_device",
    "_try_restore_from_dehydrated_device_key",
    "_extract_backup_key_from_dehydrated_device",
):
    setattr(
        KeyBackupSSSSStorageMixin,
        _method_name,
        getattr(KeyBackupSSSSStorageRecoveryMixin, _method_name),
    )

for _method_name in (
    "_get_configured_secret_storage_key_bytes",
    "_get_ssss_key_cache",
    "_get_ssss_key_info_cache",
    "_cache_secret_storage_key",
    "get_secret_storage_key_bytes",
    "get_default_secret_storage_key_id",
    "get_secret_storage_key_data",
    "_decode_secret_storage_key_payload",
):
    setattr(
        KeyBackupSSSSStorageMixin,
        _method_name,
        getattr(KeyBackupSSSSStorageCacheMixin, _method_name),
    )

for _method_name in (
    "_secret_storage_key_matches",
    "_resolve_secret_storage_key",
    "_resolve_secret_storage_context",
    "_build_secret_storage_key_account_data",
):
    setattr(
        KeyBackupSSSSStorageMixin,
        _method_name,
        getattr(KeyBackupSSSSStorageContextMixin, _method_name),
    )


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "DEHYDRATED_DEVICE_EVENT",
    "KeyBackupSSSSStorageCacheMixin",
    "KeyBackupSSSSStorageContextMixin",
    "KeyBackupSSSSStorageMixin",
    "KeyBackupSSSSStorageRecoveryMixin",
    "MSC2697_DEHYDRATED_DEVICE_EVENT",
    "SSSS_DEFAULT_KEY",
    "SSSS_KEY_PREFIX",
    "_decode_base64",
    "_decode_recovery_key",
    "json",
    "logger",
    "secrets",
]
