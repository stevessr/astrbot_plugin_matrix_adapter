"""Secret Storage key caches and account-data lookup helpers."""

from ....constants import (
    CRYPTO_KEY_SIZE_32,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from ...verification.crypto_utils import _decode_base64


class KeyBackupSSSSStorageCacheMixin:
    """管理 Secret Storage key 的本地配置、缓存和 account data 查询。"""

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

    async def get_default_secret_storage_key_id(
        self, refresh: bool = False
    ) -> str | None:
        cached_key_id = getattr(self, "_ssss_default_key_id", None)
        if not refresh and isinstance(cached_key_id, str) and cached_key_id:
            return cached_key_id

        default_key_data = await self.client.get_global_account_data(SSSS_DEFAULT_KEY)
        key_id = (default_key_data or {}).get("key")
        self._ssss_default_key_id = (
            key_id if isinstance(key_id, str) and key_id else None
        )
        return self._ssss_default_key_id

    async def get_secret_storage_key_data(
        self, key_id: str, refresh: bool = False
    ) -> dict | None:
        if not isinstance(key_id, str) or not key_id:
            return None

        cache = self._get_ssss_key_info_cache()
        if not refresh and key_id in cache:
            return cache[key_id]

        key_data = await self.client.get_global_account_data(
            f"{SSSS_KEY_PREFIX}{key_id}"
        )
        if isinstance(key_data, dict):
            cache[key_id] = key_data
            return key_data
        return None

    def _decode_secret_storage_key_payload(self, payload: bytes) -> bytes | None:
        if not payload:
            return None

        if len(payload) == CRYPTO_KEY_SIZE_32:
            return payload

        try:
            secret_str = payload.decode("utf-8").strip()
        except Exception:
            return None

        if not secret_str:
            return None

        try:
            decoded = _decode_base64(secret_str)
        except Exception:
            return None

        if len(decoded) == CRYPTO_KEY_SIZE_32:
            return decoded
        return None
