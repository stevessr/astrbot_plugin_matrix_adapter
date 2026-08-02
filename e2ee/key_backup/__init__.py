"""
Key Backup - Matrix 密钥备份

实现 Megolm 会话密钥的服务器端备份和恢复。
使用用户配置的恢复密钥进行加密。
"""

from pathlib import Path

from astrbot.api import logger

from ...constants import CRYPTO_KEY_SIZE_32, HKDF_MEGOLM_BACKUP_INFO
from ..backup import KeyBackupBackupMixin
from ..backup.crypto_utils import _compute_hkdf, _decode_recovery_key
from ..ssss import KeyBackupSSSSMixin
from .initialization import KeyBackupInitializationMixin
from .keys import KeyBackupKeysMixin
from .properties import KeyBackupPropertiesMixin
from .storage import KeyBackupStorageMixin


class KeyBackup(KeyBackupSSSSMixin, KeyBackupBackupMixin):
    """
    密钥备份管理器

    使用用户配置的恢复密钥进行加密，支持：
    - 创建密钥备份
    - 上传 Megolm 会话密钥到备份
    - 从备份恢复密钥
    """

    pass


KeyBackup.__init__ = KeyBackupInitializationMixin.__dict__["__init__"]
KeyBackup.backup_version = KeyBackupPropertiesMixin.__dict__["backup_version"]
KeyBackup.recovery_key_bytes = KeyBackupPropertiesMixin.__dict__["recovery_key_bytes"]
KeyBackup.secret_storage_key_bytes = KeyBackupPropertiesMixin.__dict__[
    "secret_storage_key_bytes"
]
KeyBackup.load_extracted_key = KeyBackupPropertiesMixin.__dict__["load_extracted_key"]
KeyBackup.read_ssss_secret = KeyBackupPropertiesMixin.__dict__["read_ssss_secret"]
KeyBackup.write_ssss_secret = KeyBackupPropertiesMixin.__dict__["write_ssss_secret"]
KeyBackup._get_extracted_key_path = KeyBackupStorageMixin.__dict__[
    "_get_extracted_key_path"
]
KeyBackup._save_extracted_key = KeyBackupStorageMixin.__dict__["_save_extracted_key"]
KeyBackup._load_extracted_key = KeyBackupStorageMixin.__dict__["_load_extracted_key"]
KeyBackup.use_recovery_key_bytes = KeyBackupKeysMixin.__dict__["use_recovery_key_bytes"]
KeyBackup.has_local_room_keys = KeyBackupKeysMixin.__dict__["has_local_room_keys"]
KeyBackup.can_attempt_restore = KeyBackupKeysMixin.__dict__["can_attempt_restore"]
KeyBackup.should_restore_for_missing_keys = KeyBackupKeysMixin.__dict__[
    "should_restore_for_missing_keys"
]


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "HKDF_MEGOLM_BACKUP_INFO",
    "KeyBackup",
    "KeyBackupBackupMixin",
    "KeyBackupInitializationMixin",
    "KeyBackupKeysMixin",
    "KeyBackupPropertiesMixin",
    "KeyBackupSSSSMixin",
    "KeyBackupStorageMixin",
    "Path",
    "_compute_hkdf",
    "_decode_recovery_key",
    "logger",
]
