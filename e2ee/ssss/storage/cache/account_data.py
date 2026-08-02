"""Secret Storage account-data lookup and caching."""

from .....constants import SSSS_DEFAULT_KEY, SSSS_KEY_PREFIX


class KeyBackupSSSSStorageCacheAccountDataMixin:
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
