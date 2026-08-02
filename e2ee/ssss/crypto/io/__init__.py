"""Composable Secret Storage input/output mixins."""

from astrbot.api import logger

from .....constants import SSSS_BACKUP_SECRET
from ....backup.crypto_utils import _decode_recovery_key
from .read import KeyBackupSSSSStorageIOReadMixin
from .recovery import KeyBackupSSSSStorageIORecoveryMixin
from .write import KeyBackupSSSSStorageIOWriteMixin


class KeyBackupSSSSStorageIOMixin(
    KeyBackupSSSSStorageIOReadMixin,
    KeyBackupSSSSStorageIOWriteMixin,
    KeyBackupSSSSStorageIORecoveryMixin,
):
    """Secret Storage 秘密读写与恢复流程。"""

    pass


KeyBackupSSSSStorageIOMixin.read_secret_from_secret_storage = (
    KeyBackupSSSSStorageIOReadMixin.__dict__["read_secret_from_secret_storage"]
)
KeyBackupSSSSStorageIOMixin.write_secret_to_secret_storage = (
    KeyBackupSSSSStorageIOWriteMixin.__dict__["write_secret_to_secret_storage"]
)
KeyBackupSSSSStorageIOMixin._try_restore_from_secret_storage = (
    KeyBackupSSSSStorageIORecoveryMixin.__dict__["_try_restore_from_secret_storage"]
)


__all__ = [
    "KeyBackupSSSSStorageIOReadMixin",
    "KeyBackupSSSSStorageIORecoveryMixin",
    "KeyBackupSSSSStorageIOMixin",
    "KeyBackupSSSSStorageIOWriteMixin",
    "SSSS_BACKUP_SECRET",
    "_decode_recovery_key",
    "logger",
]
