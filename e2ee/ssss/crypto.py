import secrets

from astrbot.api import logger

from ...constants import CRYPTO_KEY_SIZE_32, SSSS_BACKUP_SECRET
from ..backup.crypto_utils import (
    CRYPTO_AVAILABLE,
    _aes_ctr_decrypt,
    _compute_hkdf,
    _decode_recovery_key,
)
from ..verification.crypto_utils import _decode_base64, _encode_unpadded_base64


class KeyBackupSSSSMixinCrypto:
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
