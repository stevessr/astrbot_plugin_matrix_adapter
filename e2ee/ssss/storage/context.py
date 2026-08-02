"""Secret Storage key validation and context resolution."""

import secrets

from astrbot.api import logger

from ....constants import CRYPTO_KEY_SIZE_32, SSSS_DEFAULT_KEY, SSSS_KEY_PREFIX
from ...verification.crypto_utils import _decode_base64


class KeyBackupSSSSStorageContextMixin:
    """验证 Secret Storage key 并构建可用的加密上下文。"""

    def _secret_storage_key_matches(self, key: bytes, key_data: dict | None) -> bool:
        if not key or len(key) != CRYPTO_KEY_SIZE_32:
            return False
        if not isinstance(key_data, dict) or not key_data:
            return True

        algorithm = key_data.get("algorithm")
        if algorithm and algorithm != self._SSSS_ALGORITHM:
            logger.warning(f"不支持的 Secret Storage 算法：{algorithm}")
            return False

        iv_b64 = key_data.get("iv")
        mac_b64 = key_data.get("mac")
        if not iv_b64 or not mac_b64:
            return True

        try:
            encrypted = self._encrypt_ssss_data(
                key,
                b"\x00" * CRYPTO_KEY_SIZE_32,
                secret_name="",
                iv=_decode_base64(iv_b64),
            )
            expected_mac = _decode_base64(mac_b64)
            actual_mac = _decode_base64(encrypted["mac"])
            return actual_mac == expected_mac
        except Exception as e:
            logger.warning(f"验证 Secret Storage Key 失败：{e}")
            return False

    async def _resolve_secret_storage_key(
        self, key_id: str, provided_key_bytes: bytes | None = None
    ) -> bytes | None:
        cached = self._get_ssss_key_cache().get(key_id)
        if cached:
            return cached

        key_data = await self.get_secret_storage_key_data(key_id)
        configured_key = (
            provided_key_bytes or self._get_configured_secret_storage_key_bytes()
        )
        if not configured_key:
            return None

        encrypted_map = (key_data or {}).get("encrypted")
        if isinstance(encrypted_map, dict):
            for encrypted_data in encrypted_map.values():
                decrypted_key = self._decrypt_ssss_data(
                    configured_key,
                    encrypted_data,
                    secret_name="",
                )
                candidate = self._decode_secret_storage_key_payload(
                    decrypted_key or b""
                )
                if candidate and self._secret_storage_key_matches(candidate, key_data):
                    self._cache_secret_storage_key(key_id, candidate)
                    return candidate

        if self._secret_storage_key_matches(configured_key, key_data):
            self._cache_secret_storage_key(key_id, configured_key)
            return configured_key

        return None

    async def _resolve_secret_storage_context(
        self,
        key_bytes: bytes | None = None,
        *,
        create_if_missing: bool = False,
    ) -> tuple[str, bytes] | None:
        key_id = await self.get_default_secret_storage_key_id()
        if key_id:
            resolved_key = await self._resolve_secret_storage_key(key_id, key_bytes)
            if resolved_key:
                return key_id, resolved_key
            logger.warning(f"无法解析默认 Secret Storage Key：{key_id}")
            return None

        if not create_if_missing:
            return None

        bootstrap_key = key_bytes or self._get_configured_secret_storage_key_bytes()
        if not bootstrap_key:
            logger.warning("Secret Storage 尚未初始化，且未配置可用的 recovery key")
            return None

        new_key_id = f"ssss_{secrets.token_hex(8)}"
        key_data = self._build_secret_storage_key_account_data(bootstrap_key)

        await self.client.set_global_account_data(
            f"{SSSS_KEY_PREFIX}{new_key_id}",
            key_data,
        )
        await self.client.set_global_account_data(SSSS_DEFAULT_KEY, {"key": new_key_id})

        self._ssss_default_key_id = new_key_id
        self._get_ssss_key_info_cache()[new_key_id] = key_data
        self._cache_secret_storage_key(new_key_id, bootstrap_key)

        logger.info(f"已创建最小可用 Secret Storage：default_key={new_key_id}")
        return new_key_id, bootstrap_key

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
