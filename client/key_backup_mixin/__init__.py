"""Composable Matrix room key backup operations."""

from typing import Any

from ...constants import M_KEY_BACKUP
from ..path_utils import quote_path_segment
from .preference import KeyBackupPreferenceMixin
from .rooms import KeyBackupRoomKeysMixin
from .versions import KeyBackupVersionsMixin


class KeyBackupMixin(
    KeyBackupPreferenceMixin,
    KeyBackupVersionsMixin,
    KeyBackupRoomKeysMixin,
):
    """Room key backup methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
KeyBackupMixin.get_key_backup_preference = KeyBackupPreferenceMixin.__dict__[
    "get_key_backup_preference"
]
KeyBackupMixin.set_key_backup_preference = KeyBackupPreferenceMixin.__dict__[
    "set_key_backup_preference"
]
KeyBackupMixin.get_key_backup_versions = KeyBackupVersionsMixin.__dict__[
    "get_key_backup_versions"
]
KeyBackupMixin.get_key_backup_version = KeyBackupVersionsMixin.__dict__[
    "get_key_backup_version"
]
KeyBackupMixin.create_key_backup_version = KeyBackupVersionsMixin.__dict__[
    "create_key_backup_version"
]
KeyBackupMixin.update_key_backup_version = KeyBackupVersionsMixin.__dict__[
    "update_key_backup_version"
]
KeyBackupMixin.delete_key_backup_version = KeyBackupVersionsMixin.__dict__[
    "delete_key_backup_version"
]
KeyBackupMixin.get_room_keys = KeyBackupRoomKeysMixin.__dict__["get_room_keys"]
KeyBackupMixin.get_room_keys_for_room = KeyBackupRoomKeysMixin.__dict__[
    "get_room_keys_for_room"
]
KeyBackupMixin.get_room_key_for_session = KeyBackupRoomKeysMixin.__dict__[
    "get_room_key_for_session"
]
KeyBackupMixin.store_room_keys = KeyBackupRoomKeysMixin.__dict__["store_room_keys"]
KeyBackupMixin.store_room_key_for_session = KeyBackupRoomKeysMixin.__dict__[
    "store_room_key_for_session"
]
KeyBackupMixin.delete_room_keys = KeyBackupRoomKeysMixin.__dict__["delete_room_keys"]
KeyBackupMixin.delete_room_keys_for_room = KeyBackupRoomKeysMixin.__dict__[
    "delete_room_keys_for_room"
]
KeyBackupMixin.delete_room_key_for_session = KeyBackupRoomKeysMixin.__dict__[
    "delete_room_key_for_session"
]


__all__ = ["Any", "KeyBackupMixin", "M_KEY_BACKUP", "quote_path_segment"]
