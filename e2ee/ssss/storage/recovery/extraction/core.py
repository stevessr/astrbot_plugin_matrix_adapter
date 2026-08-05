"""Backup-key extraction orchestration."""


class KeyBackupSSSSStorageExtractionOrchestratorMixin:
    """Extract the backup key from a decrypted dehydrated device."""

    def _extract_backup_key_from_dehydrated_device(
        self, provided_key_bytes: bytes, dehydrated_device: dict | None
    ) -> bytes | None:
        device_data = self._resolve_dehydrated_device_data(dehydrated_device)
        if device_data is None:
            return None

        decrypted_device = self._decrypt_dehydrated_device(
            provided_key_bytes, device_data
        )
        if decrypted_device is None:
            return None

        return self._extract_key_from_dehydrated_info(decrypted_device)


__all__ = ["KeyBackupSSSSStorageExtractionOrchestratorMixin"]
