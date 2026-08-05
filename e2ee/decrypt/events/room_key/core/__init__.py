"""m.room_key event handling orchestration (Megolm session import)."""

from .backup import E2EEManagerDecryptRoomKeyBackupMixin
from .core import E2EEManagerDecryptRoomKeyOrchestratorMixin
from .prepare import E2EEManagerDecryptRoomKeyPrepareMixin
from .session import E2EEManagerDecryptRoomKeyImportMixin
from .validate import E2EEManagerDecryptRoomKeyValidateMixin


class E2EEManagerDecryptRoomKeyCoreMixin(
    E2EEManagerDecryptRoomKeyOrchestratorMixin,
    E2EEManagerDecryptRoomKeyValidateMixin,
    E2EEManagerDecryptRoomKeyPrepareMixin,
    E2EEManagerDecryptRoomKeyImportMixin,
    E2EEManagerDecryptRoomKeyBackupMixin,
):
    """Import received Megolm room keys."""


# Preserve direct method attributes expected by parent-package __dict__ lookups.
for _mixin in (
    E2EEManagerDecryptRoomKeyBackupMixin,
    E2EEManagerDecryptRoomKeyImportMixin,
    E2EEManagerDecryptRoomKeyOrchestratorMixin,
    E2EEManagerDecryptRoomKeyPrepareMixin,
    E2EEManagerDecryptRoomKeyValidateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(E2EEManagerDecryptRoomKeyCoreMixin, _method_name, _method)


__all__ = [
    "E2EEManagerDecryptRoomKeyBackupMixin",
    "E2EEManagerDecryptRoomKeyCoreMixin",
    "E2EEManagerDecryptRoomKeyImportMixin",
    "E2EEManagerDecryptRoomKeyOrchestratorMixin",
    "E2EEManagerDecryptRoomKeyPrepareMixin",
    "E2EEManagerDecryptRoomKeyValidateMixin",
]
