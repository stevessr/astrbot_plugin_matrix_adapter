import base64
import json
import secrets

from astrbot.api import logger

from ..constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
    SSSS_BACKUP_SECRET,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from .key_backup_crypto import (
    CRYPTO_AVAILABLE,
    _aes_ctr_decrypt,
    _compute_hkdf,
    _decode_recovery_key,
)


def _encode_unpadded_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8").rstrip("=")


def _decode_base64(value: str) -> bytes:
    normalized = value.strip()
    padding = "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized + padding)


class KeyBackupSSSSMixin:
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

    async def read_secret_from_secret_storage(
        self,
        secret_name: str,
        key_bytes: bytes | None = None,
    ) -> bytes | None:
        try:
            context = await self._resolve_secret_storage_context(
                key_bytes=key_bytes,
                create_if_missing=False,
            )
            if not context:
                return None

            key_id, ssss_key = context
            secret_data = await self.client.get_global_account_data(secret_name) or {}
            encrypted_map = secret_data.get("encrypted")
            if not isinstance(encrypted_map, dict):
                return None

            encrypted_data = encrypted_map.get(key_id)
            if not isinstance(encrypted_data, dict):
                logger.warning(
                    f"Account Data '{secret_name}' 中未找到 Key ID {key_id} 的加密数据"
                )
                return None

            return self._decrypt_ssss_data(
                ssss_key,
                encrypted_data,
                secret_name=secret_name,
            )
        except Exception as e:
            logger.error(
                f"读取 Secret Storage 中的 secret 失败：{secret_name} error={e}"
            )
            return None

    async def write_secret_to_secret_storage(
        self,
        secret_name: str,
        secret_value: bytes | str,
        key_bytes: bytes | None = None,
    ) -> bool:
        try:
            context = await self._resolve_secret_storage_context(
                key_bytes=key_bytes,
                create_if_missing=True,
            )
            if not context:
                return False

            key_id, ssss_key = context
            plaintext = (
                secret_value.encode("utf-8")
                if isinstance(secret_value, str)
                else bytes(secret_value)
            )

            existing = await self.client.get_global_account_data(secret_name) or {}
            if not isinstance(existing, dict):
                existing = {}

            encrypted_map = existing.get("encrypted")
            if not isinstance(encrypted_map, dict):
                encrypted_map = {}

            encrypted_map[key_id] = self._encrypt_ssss_data(
                ssss_key,
                plaintext,
                secret_name=secret_name,
            )
            existing["encrypted"] = encrypted_map

            await self.client.set_global_account_data(secret_name, existing)
            return True
        except Exception as e:
            logger.warning(f"写入 Secret Storage 失败：secret={secret_name} error={e}")
            return False

    async def _try_restore_from_secret_storage(
        self,
        provided_key_bytes: bytes,
        *,
        include_dehydrated: bool = True,
        allow_local_short_circuit: bool = True,
    ) -> bytes | None:
        """
        尝试从 Secret Storage 解密真正的备份密钥
        支持直接解密和通过 Recovery Key 解密 SSSS Key 的链式解密
        """
        logger.info("尝试从 Secret Storage 恢复密钥...")
        try:
            local_recovery_key = (
                self._get_valid_local_recovery_key_bytes()
                if allow_local_short_circuit
                else None
            )
            if local_recovery_key:
                logger.info("本地恢复密钥已存在且验证通过，跳过 dehydrated device 恢复")
                return local_recovery_key

            if include_dehydrated:
                dehydrated_key = await self._try_restore_from_dehydrated_device_key(
                    provided_key_bytes
                )
                if dehydrated_key:
                    return dehydrated_key

            decrypted_secret = await self.read_secret_from_secret_storage(
                SSSS_BACKUP_SECRET,
                key_bytes=provided_key_bytes,
            )
            if decrypted_secret:
                logger.info("SSSS MAC 验证成功，解密备份密钥成功")
                try:
                    secret_str = decrypted_secret.decode("utf-8").strip()
                    if secret_str:
                        try:
                            return _decode_recovery_key(secret_str)
                        except Exception:
                            pass
                    return decrypted_secret
                except Exception:
                    return decrypted_secret

            logger.error("SSSS MAC 验证失败！提供的密钥（或解密出的 SSSS Key）不正确")
            return None

        except Exception as e:
            logger.error(f"SSSS 恢复失败：{e}")
            import traceback

            logger.error(traceback.format_exc())
            return None

    def _encrypt_ssss_data(
        self,
        key: bytes,
        plaintext: bytes,
        secret_name: str = "",
        iv: bytes | None = None,
    ) -> dict[str, str]:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("缺少 cryptography 库，无法进行 SSSS 加密")

        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import hmac as crypto_hmac
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except Exception as e:
            raise RuntimeError(f"cryptography 不可用，无法执行 SSSS 加密：{e}") from e

        if not key or len(key) != CRYPTO_KEY_SIZE_32:
            raise ValueError("SSSS key 必须是 32 字节")

        if iv is None:
            iv_bytes = bytearray(secrets.token_bytes(16))
            iv_bytes[8] &= 0x7F
            iv = bytes(iv_bytes)
        elif len(iv) != 16:
            raise ValueError("SSSS IV 必须是 16 字节")

        info = secret_name.encode("utf-8") if secret_name else b""
        salt = b"\x00" * CRYPTO_KEY_SIZE_32
        derived = _compute_hkdf(key, salt, info, length=64)
        aes_key = derived[:CRYPTO_KEY_SIZE_32]
        hmac_key = derived[CRYPTO_KEY_SIZE_32:64]

        cipher = Cipher(
            algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        mac = h.finalize()

        return {
            "ciphertext": _encode_unpadded_base64(ciphertext),
            "iv": _encode_unpadded_base64(iv),
            "mac": _encode_unpadded_base64(mac),
        }

    def _decrypt_ssss_data(
        self, key: bytes, encrypted_data: dict, secret_name: str = ""
    ) -> bytes | None:
        """
        解密 SSSS 加密的数据 (AES-CTR-256 + HMAC-SHA-256)

        Per Matrix spec (m.secret_storage.v1.aes-hmac-sha2):
        - Use HKDF to derive 64 bytes from the key
        - First 32 bytes: AES-CTR key
        - Next 32 bytes: HMAC-SHA-256 key
        - HKDF uses SHA-256, 32-byte zero salt, and secret name as info
        """
        ciphertext_b64 = encrypted_data.get("ciphertext")
        iv_b64 = encrypted_data.get("iv")
        mac_b64 = encrypted_data.get("mac")

        if not ciphertext_b64 or not iv_b64 or not mac_b64:
            return None

        try:
            ciphertext = _decode_base64(ciphertext_b64)
            iv = _decode_base64(iv_b64)
            mac = _decode_base64(mac_b64)
        except Exception:
            return None

        if not CRYPTO_AVAILABLE:
            logger.error("缺少 cryptography 库，无法进行 SSSS 解密")
            return None

        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import hmac as crypto_hmac
        except Exception:
            logger.error("cryptography 不可用，无法验证 SSSS MAC")
            return None

        # Derive AES and MAC keys using HKDF per Matrix spec
        # HKDF(SHA-256, key, 32-byte zero salt, secret_name as info) -> 64 bytes
        try:
            # Use secret name as info for HKDF derivation
            info = secret_name.encode() if secret_name else b""
            salt = b"\x00" * CRYPTO_KEY_SIZE_32  # Zero salt per spec

            derived = _compute_hkdf(key, salt, info, length=64)
            aes_key = derived[:CRYPTO_KEY_SIZE_32]
            hmac_key = derived[CRYPTO_KEY_SIZE_32:64]

            logger.debug(f"SSSS 密钥派生：info={repr(info)}, 派生 64 字节")
        except Exception as e:
            logger.warning(f"HKDF 密钥派生失败：{e}, 使用原始密钥")
            # Fallback: use key directly (backward compatibility)
            aes_key = key
            hmac_key = key

        # Verify MAC
        try:
            h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(ciphertext)
            try:
                h.verify(mac)
            except Exception:
                return None

            # Decrypt
            return _aes_ctr_decrypt(aes_key, iv, ciphertext)
        except Exception as e:
            logger.warning(f"解密异常：{e}")
            return None
