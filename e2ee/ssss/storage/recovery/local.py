"""Validation of locally persisted recovery-key material."""

from .....constants import CRYPTO_KEY_SIZE_32


class KeyBackupSSSSStorageLocalRecoveryMixin:
    def _get_valid_local_recovery_key_bytes(self) -> bytes | None:
        verify = getattr(self, "_verify_recovery_key", None)

        current_key = getattr(self, "_recovery_key_bytes", None)
        if (
            isinstance(current_key, (bytes, bytearray))
            and len(current_key) == CRYPTO_KEY_SIZE_32
        ):
            key_bytes = bytes(current_key)
            if not callable(verify):
                return key_bytes
            try:
                if verify(key_bytes, log_mismatch=False):
                    return key_bytes
            except TypeError:
                if verify(key_bytes):
                    return key_bytes

        load_extracted_key = getattr(self, "_load_extracted_key", None)
        if not callable(load_extracted_key):
            return None

        extracted_key = load_extracted_key()
        if not isinstance(extracted_key, (bytes, bytearray)):
            return None
        if len(extracted_key) != CRYPTO_KEY_SIZE_32:
            return None

        key_bytes = bytes(extracted_key)
        if not callable(verify):
            return key_bytes
        try:
            if verify(key_bytes, log_mismatch=False):
                return key_bytes
        except TypeError:
            if verify(key_bytes):
                return key_bytes
        return None
