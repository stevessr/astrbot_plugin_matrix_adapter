"""Composable Secret Storage cache mixins."""

from .....constants import (
    CRYPTO_KEY_SIZE_32,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from ....verification.crypto_utils import _decode_base64
from .account_data import KeyBackupSSSSStorageCacheAccountDataMixin
from .decoding import KeyBackupSSSSStorageCacheDecodingMixin
from .state import KeyBackupSSSSStorageCacheStateMixin


class KeyBackupSSSSStorageCacheMixin(
    KeyBackupSSSSStorageCacheStateMixin,
    KeyBackupSSSSStorageCacheAccountDataMixin,
    KeyBackupSSSSStorageCacheDecodingMixin,
):
    """管理 Secret Storage key 的本地配置、缓存和 account data 查询。"""

    pass


for _method_name in (
    "_get_configured_secret_storage_key_bytes",
    "_get_ssss_key_cache",
    "_get_ssss_key_info_cache",
    "_cache_secret_storage_key",
    "get_secret_storage_key_bytes",
):
    setattr(
        KeyBackupSSSSStorageCacheMixin,
        _method_name,
        getattr(KeyBackupSSSSStorageCacheStateMixin, _method_name),
    )

for _method_name in (
    "get_default_secret_storage_key_id",
    "get_secret_storage_key_data",
):
    setattr(
        KeyBackupSSSSStorageCacheMixin,
        _method_name,
        getattr(KeyBackupSSSSStorageCacheAccountDataMixin, _method_name),
    )

KeyBackupSSSSStorageCacheMixin._decode_secret_storage_key_payload = (
    KeyBackupSSSSStorageCacheDecodingMixin._decode_secret_storage_key_payload
)


__all__ = [
    "CRYPTO_KEY_SIZE_32",
    "KeyBackupSSSSStorageCacheAccountDataMixin",
    "KeyBackupSSSSStorageCacheDecodingMixin",
    "KeyBackupSSSSStorageCacheMixin",
    "KeyBackupSSSSStorageCacheStateMixin",
    "SSSS_DEFAULT_KEY",
    "SSSS_KEY_PREFIX",
    "_decode_base64",
]
