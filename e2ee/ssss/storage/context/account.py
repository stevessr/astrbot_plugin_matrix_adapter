"""Minimal Secret Storage account-data construction."""

from .....constants import CRYPTO_KEY_SIZE_32


class KeyBackupSSSSStorageContextAccountMixin:
    def _build_secret_storage_key_account_data(self, key_bytes: bytes) -> dict:
        validation_data = self._encrypt_ssss_data(
            key_bytes,
            b"\x00" * CRYPTO_KEY_SIZE_32,
            secret_name="",
        )
        return {
            "algorithm": self._SSSS_ALGORITHM,
            "name": self._SSSS_BOOTSTRAP_KEY_NAME,
            "iv": validation_data["iv"],
            "mac": validation_data["mac"],
        }
