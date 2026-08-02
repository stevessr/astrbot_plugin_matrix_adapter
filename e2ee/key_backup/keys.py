"""Recovery-key state and restore eligibility helpers."""

from ...constants import CRYPTO_KEY_SIZE_32, HKDF_MEGOLM_BACKUP_INFO
from ..backup.crypto_utils import _compute_hkdf


class KeyBackupKeysMixin:
    def use_recovery_key_bytes(self, key_bytes: bytes, persist: bool = False) -> bool:
        """Set current backup key bytes and derive encryption key."""
        if not key_bytes or len(key_bytes) != CRYPTO_KEY_SIZE_32:
            return False
        self._recovery_key_bytes = key_bytes
        self._encryption_key = _compute_hkdf(
            self._recovery_key_bytes, b"", HKDF_MEGOLM_BACKUP_INFO
        )
        if persist:
            self._save_extracted_key(key_bytes)
        return True

    def has_local_room_keys(self) -> bool:
        """Whether current account already has inbound Megolm keys locally."""
        try:
            return self.store.get_megolm_inbound_count() > 0
        except Exception:
            return bool(getattr(self.store, "_megolm_inbound", {}))

    def can_attempt_restore(self) -> bool:
        """Whether backup restore can be attempted with current state."""
        return bool(self._backup_version and self._recovery_key_bytes)

    def should_restore_for_missing_keys(self) -> bool:
        """Only restore when this account is missing local keys."""
        return self.can_attempt_restore() and not self.has_local_room_keys()
