"""Secret Storage read, write, and recovery orchestration."""

from astrbot.api import logger

from ....constants import SSSS_BACKUP_SECRET
from ...backup.crypto_utils import _decode_recovery_key


class KeyBackupSSSSStorageIOMixin:
    """Secret Storage 秘密读写与恢复流程。"""

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
