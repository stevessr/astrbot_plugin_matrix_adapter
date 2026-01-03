import base64
import json

from astrbot.api import logger

from ..constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
    SSSS_BACKUP_SECRET,
    SSSS_DEFAULT_KEY,
    SSSS_KEY_PREFIX,
)
from .key_backup_crypto import CRYPTO_AVAILABLE, _aes_ctr_decrypt, _compute_hkdf


class KeyBackupSSSSMixin:
    async def _try_restore_from_secret_storage(
        self, provided_key_bytes: bytes
    ) -> bytes | None:
        """
        尝试从 Secret Storage 解密真正的备份密钥
        支持直接解密和通过 Recovery Key 解密 SSSS Key 的链式解密
        """
        logger.info("尝试从 Secret Storage 恢复密钥...")
        dehydrated_device = None
        try:
            # 1. Get default key ID
            default_key_data = await self.client.get_global_account_data(
                SSSS_DEFAULT_KEY
            )
            key_id = default_key_data.get("key")
            if not key_id:
                logger.warning(
                    "SSSS Account Data 'm.secret_storage.default_key' 未找到或无 'key'"
                )
                return None

            logger.info(f"SSSS Default Key ID: {key_id}")

            # 2. Try to decrypt the SSSS Key itself (if it's encrypted by the provided key)
            # Fetch key definition
            key_data = await self.client.get_global_account_data(
                f"{SSSS_KEY_PREFIX}{key_id}"
            )
            # DEBUG LOGGING
            if key_data:
                logger.info(f"Key Data for {key_id}: keys={list(key_data.keys())}")
                if "encrypted" in key_data:
                    logger.info(
                        f"Key {key_id} has encrypted data: {list(key_data['encrypted'].keys())}"
                    )
                else:
                    logger.warning(
                        f"Key data for {key_id} does not contain 'encrypted' section"
                    )
            else:
                logger.warning(f"Could not fetch data for key {key_id}")
                # Check for Dehydrated Device
                dehydrated_device = await self.client.get_global_account_data(
                    DEHYDRATED_DEVICE_EVENT
                )
                if not dehydrated_device:
                    dehydrated_device = await self.client.get_global_account_data(
                        MSC2697_DEHYDRATED_DEVICE_EVENT
                    )
                    if dehydrated_device:
                        logger.info("Found MSC2697 dehydrated device event")
            if dehydrated_device:
                logger.info(
                    f"Found dehydrated device event: {dehydrated_device.keys()}"
                )
                device_data = dehydrated_device.get("device_data", {})
                if device_data:
                    logger.info(f"Dehydrated device data keys: {device_data.keys()}")
                    # Try to decrypt using provided key (dehydrated device key from FluffyChat)
                    # Dehydrated device uses "org.matrix.msc2697.dehydrated_device" or "m.dehydrated_device" as secret name
                    decrypted_device = self._decrypt_ssss_data(
                        provided_key_bytes,
                        device_data,
                        secret_name="m.dehydrated_device",
                    )
                    if decrypted_device:
                        logger.info("✅ Successfully decrypted Dehydrated Device data!")
                        # The decrypted data might contain the actual backup recovery key
                        # Try to extract it and use it as the SSSS key
                        try:
                            # Try to parse as JSON first
                            try:
                                device_info = json.loads(decrypted_device)
                                logger.info(
                                    f"Decrypted Dehydrated Device Info keys: {device_info.keys()}"
                                )

                                # Look for backup key in common locations
                                # FluffyChat might store it as 'm.megolm_backup.v1' or similar
                                backup_key = None
                                if "m.megolm_backup.v1" in device_info:
                                    backup_key = device_info["m.megolm_backup.v1"]
                                    logger.info(
                                        "Found backup key in dehydrated device: m.megolm_backup.v1"
                                    )
                                elif "backup_key" in device_info:
                                    backup_key = device_info["backup_key"]
                                    logger.info(
                                        "Found backup key in dehydrated device: backup_key"
                                    )

                                if backup_key:
                                    # The backup key might be base64 encoded
                                    if isinstance(backup_key, str):
                                        try:
                                            extracted_key = base64.b64decode(backup_key)
                                            logger.info(
                                                f"✅ Extracted backup key from dehydrated device ({len(extracted_key)} bytes)"
                                            )
                                            # Use this as the actual recovery key!
                                            return extracted_key
                                        except Exception:
                                            logger.warning(
                                                "Failed to base64 decode backup key from device"
                                            )
                                    elif isinstance(backup_key, bytes):
                                        logger.info(
                                            f"✅ Extracted backup key from dehydrated device ({len(backup_key)} bytes)"
                                        )
                                        return backup_key

                            except (json.JSONDecodeError, ValueError):
                                # Not JSON, might be pickled Olm account or raw key material
                                logger.info(
                                    f"Decrypted Dehydrated Device data is not JSON (len: {len(decrypted_device)})"
                                )
                                # If it's exactly 32 bytes, it might be the raw backup key
                                if len(decrypted_device) == CRYPTO_KEY_SIZE_32:
                                    logger.info(
                                        "✅ Dehydrated device data is exactly 32 bytes, using as backup key"
                                    )
                                    return decrypted_device
                        except Exception as e:
                            logger.warning(
                                f"Failed to extract backup key from dehydrated device: {e}"
                            )
                    else:
                        logger.warning(
                            "Failed to decrypt Dehydrated Device with provided key"
                        )
            else:
                logger.info("No dehydrated device event found")

            ssss_key = provided_key_bytes
            # If the key definition contains 'encrypted', it means the actual SSSS key is encrypted
            # (usually by the Recovery Key or Passphrase)
            if key_data and "encrypted" in key_data:
                logger.info(f"检测到 SSSS Key {key_id} 是加密存储的，尝试解密...")
                encrypted_map = key_data["encrypted"]
                decrypted_ssss_key = None

                # Try all entries in the encrypted map
                for kid, enc_data in encrypted_map.items():
                    # The SSSS key itself uses empty string as secret name
                    decrypted = self._decrypt_ssss_data(
                        provided_key_bytes, enc_data, secret_name=""
                    )
                    if decrypted:
                        logger.info(f"成功使用提供的密钥解密了 SSSS Key (ID: {kid})")
                        decrypted_ssss_key = decrypted
                        break

                if decrypted_ssss_key:
                    # Check if the decrypted key is base64 encoded (it usually is in SSSS)
                    try:
                        # SSSS keys are often stored as base64 string in the payload
                        secret_str = decrypted_ssss_key.decode("utf-8")
                        if len(secret_str.strip()) >= 43:
                            ssss_key = base64.b64decode(secret_str)
                        else:
                            ssss_key = decrypted_ssss_key
                    except Exception:
                        ssss_key = decrypted_ssss_key
                else:
                    logger.warning(
                        "无法解密 SSSS Key，尝试直接使用提供的密钥作为 SSSS Key..."
                    )

            # 3. Get Backup Secret (m.megolm_backup.v1)
            backup_secret_data = await self.client.get_global_account_data(
                SSSS_BACKUP_SECRET
            )
            encrypted_data = backup_secret_data.get("encrypted", {}).get(key_id)

            if not encrypted_data:
                logger.warning(
                    f"Account Data 'm.megolm_backup.v1' 中未找到 Key ID {key_id} 的加密数据"
                )
                return None

            # 4. Decrypt Backup Key using SSSS Key
            # Use the backup secret name (m.megolm_backup.v1) as info for HKDF
            decrypted_secret = self._decrypt_ssss_data(
                ssss_key, encrypted_data, secret_name=SSSS_BACKUP_SECRET
            )

            if decrypted_secret:
                logger.info("SSSS MAC 验证成功，解密备份密钥成功")
                # Check format (usually base64 string in Matrix)
                try:
                    secret_str = decrypted_secret.decode("utf-8")
                    if len(secret_str.strip()) >= 43:
                        return base64.b64decode(secret_str)
                    return decrypted_secret
                except Exception:
                    return decrypted_secret
            else:
                logger.error(
                    "SSSS MAC 验证失败！提供的密钥（或解密出的 SSSS Key）不正确"
                )
                return None

        except Exception as e:
            logger.error(f"SSSS 恢复失败：{e}")
            import traceback

            logger.error(traceback.format_exc())
            return None

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
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            mac = base64.b64decode(mac_b64)
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
