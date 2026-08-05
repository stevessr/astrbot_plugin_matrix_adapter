"""Extraction of backup keys from decrypted dehydrated-device data."""

from .core import KeyBackupSSSSStorageExtractionOrchestratorMixin
from .decrypt import KeyBackupSSSSStorageDecryptDeviceMixin
from .device import KeyBackupSSSSStorageDeviceDataMixin
from .key import KeyBackupSSSSStorageKeyExtractMixin


class KeyBackupSSSSStorageExtractionMixin(
    KeyBackupSSSSStorageExtractionOrchestratorMixin,
    KeyBackupSSSSStorageDeviceDataMixin,
    KeyBackupSSSSStorageDecryptDeviceMixin,
    KeyBackupSSSSStorageKeyExtractMixin,
):
    """Extract the backup key from decrypted dehydrated-device data."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    KeyBackupSSSSStorageExtractionOrchestratorMixin,
    KeyBackupSSSSStorageDeviceDataMixin,
    KeyBackupSSSSStorageDecryptDeviceMixin,
    KeyBackupSSSSStorageKeyExtractMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(KeyBackupSSSSStorageExtractionMixin, _method_name, _method)


__all__ = [
    "KeyBackupSSSSStorageDecryptDeviceMixin",
    "KeyBackupSSSSStorageDeviceDataMixin",
    "KeyBackupSSSSStorageExtractionMixin",
    "KeyBackupSSSSStorageExtractionOrchestratorMixin",
    "KeyBackupSSSSStorageKeyExtractMixin",
]
