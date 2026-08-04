"""Matrix room key backup room and session operations.

Public symbols re-exported for backward compatibility.
"""

from .deletion import KeyBackupRoomKeysDeletionMixin
from .retrieval import KeyBackupRoomKeysRetrievalMixin
from .storage import KeyBackupRoomKeysStorageMixin


class KeyBackupRoomKeysMixin(
    KeyBackupRoomKeysRetrievalMixin,
    KeyBackupRoomKeysStorageMixin,
    KeyBackupRoomKeysDeletionMixin,
):
    """Room key backup key retrieval, storage, and deletion."""


# Preserve direct method attributes exposed by the former mixin.
for _mixin in (
    KeyBackupRoomKeysRetrievalMixin,
    KeyBackupRoomKeysStorageMixin,
    KeyBackupRoomKeysDeletionMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(KeyBackupRoomKeysMixin, _method_name, _method)


__all__ = [
    "KeyBackupRoomKeysDeletionMixin",
    "KeyBackupRoomKeysMixin",
    "KeyBackupRoomKeysRetrievalMixin",
    "KeyBackupRoomKeysStorageMixin",
]
