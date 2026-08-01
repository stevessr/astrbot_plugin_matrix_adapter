import json
import secrets

from astrbot.api import logger

from ...constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from ..backup.crypto_utils import _decode_recovery_key
from ..verification.crypto_utils import _decode_base64


class KeyBackupSSSSStorageMixin:
    _SSSS_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
    _SSSS_BOOTSTRAP_KEY_NAME = "AstrBot Secret Storage"

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

    async def _get_dehydrated_device(self) -> dict | None:
        dehydrated_device = await self.client.get_global_account_data(
            DEHYDRATED_DEVICE_EVENT
        )
        if dehydrated_device:
            logger.info("Found stable dehydrated device event")
            return dehydrated_device

        dehydrated_device = await self.client.get_global_account_data(
            MSC2697_DEHYDRATED_DEVICE_EVENT
        )
        if dehydrated_device:
            logger.info("Found MSC2697 dehydrated device event")

        return dehydrated_device

    async def _try_restore_from_dehydrated_device_key(
        self, provided_key_bytes: bytes
    ) -> bytes | None:
        if not provided_key_bytes:
            return None

        dehydrated_device = await self._get_dehydrated_device()
        return self._extract_backup_key_from_dehydrated_device(
            provided_key_bytes,
            dehydrated_device,
        )

    def _extract_backup_key_from_dehydrated_device(
        self, provided_key_bytes: bytes, dehydrated_device: dict | None
    ) -> bytes | None:
        if not dehydrated_device:
            logger.info("No dehydrated device event found")
            return None

        logger.info(f"Found dehydrated device event: {dehydrated_device.keys()}")
        device_data = dehydrated_device.get("device_data")
        if not isinstance(device_data, dict):
            device_data = (
                dehydrated_device if isinstance(dehydrated_device, dict) else {}
            )

        if not device_data:
            logger.warning(
                "Dehydrated device event does not contain usable device data"
            )
            return None

        logger.info(f"Dehydrated device data keys: {device_data.keys()}")

        decrypted_device = None
        for secret_name in (
            DEHYDRATED_DEVICE_EVENT,
            MSC2697_DEHYDRATED_DEVICE_EVENT,
        ):
            decrypted_device = self._decrypt_ssss_data(
                provided_key_bytes,
                device_data,
                secret_name=secret_name,
            )
            if decrypted_device:
                logger.info(
                    "✅ Successfully decrypted Dehydrated Device data "
                    f"with secret name {secret_name}!"
                )
                break

        if not decrypted_device:
            logger.warning("Failed to decrypt Dehydrated Device with provided key")
            return None

        try:
            try:
                device_info = json.loads(decrypted_device)
                logger.info(
                    f"Decrypted Dehydrated Device Info keys: {device_info.keys()}"
                )

                backup_key = None
                if "m.megolm_backup.v1" in device_info:
                    backup_key = device_info["m.megolm_backup.v1"]
                    logger.info(
                        "Found backup key in dehydrated device: m.megolm_backup.v1"
                    )
                elif "backup_key" in device_info:
                    backup_key = device_info["backup_key"]
                    logger.info("Found backup key in dehydrated device: backup_key")
                elif "recovery_key" in device_info:
                    backup_key = device_info["recovery_key"]
                    logger.info("Found backup key in dehydrated device: recovery_key")

                if backup_key:
                    if isinstance(backup_key, str):
                        try:
                            extracted_key = _decode_recovery_key(backup_key)
                            logger.info(
                                "✅ Extracted backup key from dehydrated device "
                                f"({len(extracted_key)} bytes)"
                            )
                            return extracted_key
                        except Exception:
                            logger.warning("Failed to decode backup key from device")
                    elif isinstance(backup_key, bytes):
                        if len(backup_key) == CRYPTO_KEY_SIZE_32:
                            logger.info(
                                "✅ Extracted backup key from dehydrated device "
                                f"({len(backup_key)} bytes)"
                            )
                            return backup_key

            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                logger.info(
                    "Decrypted Dehydrated Device data is not JSON "
                    f"(len: {len(decrypted_device)})"
                )
                if len(decrypted_device) == CRYPTO_KEY_SIZE_32:
                    logger.info(
                        "✅ Dehydrated device data is exactly 32 bytes, using as backup key"
                    )
                    return decrypted_device
        except Exception as e:
            logger.warning(f"Failed to extract backup key from dehydrated device: {e}")

        return None

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
