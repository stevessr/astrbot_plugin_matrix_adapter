"""Room-session restoration from Matrix key backups."""

from .core import KeyBackupRoomKeysRestoreOrchestratorMixin
from .decryption import KeyBackupRoomKeysRestoreDecryptionMixin
from .key import KeyBackupRoomKeysRestoreKeyMixin
from .sessions import KeyBackupRoomKeysRestoreSessionsMixin


class KeyBackupRoomKeysRestoreCoreMixin(
    KeyBackupRoomKeysRestoreOrchestratorMixin,
    KeyBackupRoomKeysRestoreKeyMixin,
    KeyBackupRoomKeysRestoreDecryptionMixin,
    KeyBackupRoomKeysRestoreSessionsMixin,
):
    """从密钥备份恢复房间会话。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    KeyBackupRoomKeysRestoreOrchestratorMixin,
    KeyBackupRoomKeysRestoreKeyMixin,
    KeyBackupRoomKeysRestoreDecryptionMixin,
    KeyBackupRoomKeysRestoreSessionsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(KeyBackupRoomKeysRestoreCoreMixin, _method_name, _method)


__all__ = [
    "KeyBackupRoomKeysRestoreCoreMixin",
    "KeyBackupRoomKeysRestoreDecryptionMixin",
    "KeyBackupRoomKeysRestoreKeyMixin",
    "KeyBackupRoomKeysRestoreOrchestratorMixin",
    "KeyBackupRoomKeysRestoreSessionsMixin",
]
