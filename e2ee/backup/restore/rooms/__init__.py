"""Room-session restoration from Matrix key backups, split by responsibility.

Public symbols re-exported for backward compatibility.
"""

from .core import KeyBackupRoomKeysRestoreCoreMixin
from .session import KeyBackupRoomKeysRestoreSessionMixin


class KeyBackupRoomKeysRestoreMixin(
    KeyBackupRoomKeysRestoreCoreMixin,
    KeyBackupRoomKeysRestoreSessionMixin,
):
    """从密钥备份恢复房间会话。"""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    KeyBackupRoomKeysRestoreCoreMixin,
    KeyBackupRoomKeysRestoreSessionMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(KeyBackupRoomKeysRestoreMixin, _method_name, _method)


__all__ = [
    "KeyBackupRoomKeysRestoreMixin",
    "KeyBackupRoomKeysRestoreCoreMixin",
    "KeyBackupRoomKeysRestoreSessionMixin",
]
