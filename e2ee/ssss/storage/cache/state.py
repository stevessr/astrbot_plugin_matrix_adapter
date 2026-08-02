"""Configured Secret Storage key and in-memory cache state."""

from .....constants import CRYPTO_KEY_SIZE_32


class KeyBackupSSSSStorageCacheStateMixin:
    def _get_configured_secret_storage_key_bytes(self) -> bytes | None:
        key_bytes = getattr(self, "_provided_secret_storage_key_bytes", None)
        if (
            isinstance(key_bytes, (bytes, bytearray))
            and len(key_bytes) == CRYPTO_KEY_SIZE_32
        ):
            return bytes(key_bytes)
        return None

    def _get_ssss_key_cache(self) -> dict[str, bytes]:
        cache = getattr(self, "_ssss_key_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            self._ssss_key_cache = cache
        return cache

    def _get_ssss_key_info_cache(self) -> dict[str, dict]:
        cache = getattr(self, "_ssss_key_info_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            self._ssss_key_info_cache = cache
        return cache

    def _cache_secret_storage_key(self, key_id: str, key_bytes: bytes) -> None:
        if not key_id or not key_bytes:
            return
        self._get_ssss_key_cache()[key_id] = key_bytes

    def get_secret_storage_key_bytes(self) -> bytes | None:
        default_key_id = getattr(self, "_ssss_default_key_id", None)
        if isinstance(default_key_id, str) and default_key_id:
            cached = self._get_ssss_key_cache().get(default_key_id)
            if cached:
                return cached
        return self._get_configured_secret_storage_key_bytes()
