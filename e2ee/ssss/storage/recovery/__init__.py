"""Composable dehydrated-device recovery mixins."""

import json

from astrbot.api import logger

from .....constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
)
from ....backup.crypto_utils import _decode_recovery_key
from .dehydrated import KeyBackupSSSSStorageDehydratedMixin
from .extraction import KeyBackupSSSSStorageExtractionMixin
from .local import KeyBackupSSSSStorageLocalRecoveryMixin


class KeyBackupSSSSStorageRecoveryMixin(
    KeyBackupSSSSStorageLocalRecoveryMixin,
    KeyBackupSSSSStorageDehydratedMixin,
    KeyBackupSSSSStorageExtractionMixin,
):
    """从 dehydrated device account data 恢复房间备份密钥。"""

    pass


KeyBackupSSSSStorageRecoveryMixin._get_valid_local_recovery_key_bytes = (
    KeyBackupSSSSStorageLocalRecoveryMixin.__dict__[
        "_get_valid_local_recovery_key_bytes"
    ]
)
KeyBackupSSSSStorageRecoveryMixin._get_dehydrated_device = (
    KeyBackupSSSSStorageDehydratedMixin.__dict__["_get_dehydrated_device"]
)
KeyBackupSSSSStorageRecoveryMixin._try_restore_from_dehydrated_device_key = (
    KeyBackupSSSSStorageDehydratedMixin.__dict__[
        "_try_restore_from_dehydrated_device_key"
    ]
)
KeyBackupSSSSStorageRecoveryMixin._extract_backup_key_from_dehydrated_device = (
    KeyBackupSSSSStorageExtractionMixin.__dict__[
        "_extract_backup_key_from_dehydrated_device"
    ]
)


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "DEHYDRATED_DEVICE_EVENT",
    "KeyBackupSSSSStorageDehydratedMixin",
    "KeyBackupSSSSStorageExtractionMixin",
    "KeyBackupSSSSStorageLocalRecoveryMixin",
    "KeyBackupSSSSStorageRecoveryMixin",
    "MSC2697_DEHYDRATED_DEVICE_EVENT",
    "_decode_recovery_key",
    "json",
    "logger",
]
