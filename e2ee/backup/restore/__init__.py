"""Composable Matrix key-backup restoration operations."""

import json
import time

from astrbot.api import logger

from ....constants import AES_GCM_NONCE_LEN, CRYPTO_KEY_SIZE_32
from ..crypto_utils import (
    VODOZEMAC_PK_AVAILABLE,
    Curve25519SecretKey,
    PkDecryption,
    _decode_recovery_key,
    _decrypt_backup_data,
)
from .initialization import KeyBackupRestoreInitializationMixin
from .policy import KeyBackupRestorePolicyMixin
from .rooms import KeyBackupRoomKeysRestoreMixin


class KeyBackupBackupRestoreMixin(
    KeyBackupRestoreInitializationMixin,
    KeyBackupRestorePolicyMixin,
    KeyBackupRoomKeysRestoreMixin,
):
    """分层处理密钥备份初始化、恢复策略和房间会话恢复。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in ("initialize",):
    setattr(
        KeyBackupBackupRestoreMixin,
        _method_name,
        getattr(KeyBackupRestoreInitializationMixin, _method_name),
    )

for _method_name in ("should_restore_for_session", "restore_room_keys_if_needed"):
    setattr(
        KeyBackupBackupRestoreMixin,
        _method_name,
        getattr(KeyBackupRestorePolicyMixin, _method_name),
    )

for _method_name in ("restore_room_keys",):
    setattr(
        KeyBackupBackupRestoreMixin,
        _method_name,
        getattr(KeyBackupRoomKeysRestoreMixin, _method_name),
    )


__all__ = [
    "AES_GCM_NONCE_LEN",
    "CRYPTO_KEY_SIZE_32",
    "Curve25519SecretKey",
    "KeyBackupBackupRestoreMixin",
    "KeyBackupRestoreInitializationMixin",
    "KeyBackupRestorePolicyMixin",
    "KeyBackupRoomKeysRestoreMixin",
    "PkDecryption",
    "VODOZEMAC_PK_AVAILABLE",
    "_decode_recovery_key",
    "_decrypt_backup_data",
    "json",
    "logger",
    "time",
]
