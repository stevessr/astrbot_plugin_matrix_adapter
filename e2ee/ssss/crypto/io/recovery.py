"""Recovery of backup keys through Secret Storage."""

from astrbot.api import logger

from .....constants import SSSS_BACKUP_SECRET
from ....backup.crypto_utils import _decode_recovery_key


class KeyBackupSSSSStorageIORecoveryMixin:
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
