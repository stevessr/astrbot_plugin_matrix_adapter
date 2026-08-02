"""Composable Matrix key-backup upload operations."""

import base64
import json
import secrets

from astrbot.api import logger

from ....constants import (
    CRYPTO_KEY_SIZE_32,
    MEGOLM_ALGO,
    MEGOLM_BACKUP_ALGO,
)
from ..crypto_utils import (
    _compute_hkdf,
    _encode_recovery_key,
)
from .lifecycle import KeyBackupUploadLifecycleMixin
from .rooms import KeyBackupUploadRoomsMixin
from .session import KeyBackupUploadSessionMixin


class KeyBackupBackupUploadMixin(
    KeyBackupUploadLifecycleMixin,
    KeyBackupUploadRoomsMixin,
    KeyBackupUploadSessionMixin,
):
    """生成备份并上传房间会话密钥。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in ("_get_current_backup_version", "create_backup"):
    setattr(
        KeyBackupBackupUploadMixin,
        _method_name,
        getattr(KeyBackupUploadLifecycleMixin, _method_name),
    )

KeyBackupBackupUploadMixin.upload_room_keys = KeyBackupUploadRoomsMixin.upload_room_keys
KeyBackupBackupUploadMixin.upload_single_key = (
    KeyBackupUploadSessionMixin.upload_single_key
)


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupBackupUploadMixin",
    "KeyBackupUploadLifecycleMixin",
    "KeyBackupUploadRoomsMixin",
    "KeyBackupUploadSessionMixin",
    "MEGOLM_ALGO",
    "MEGOLM_BACKUP_ALGO",
    "_compute_hkdf",
    "_encode_recovery_key",
    "base64",
    "json",
    "logger",
    "secrets",
]
