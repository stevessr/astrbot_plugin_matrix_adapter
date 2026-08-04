"""Store received secrets by type (backup key, cross-signing keys)."""

import base64

from astrbot.api import logger

from .....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)


class E2EEManagerSecretsReceiveStoreMixin:
    """把接收到的秘密写入对应密钥存储。"""

    async def _process_received_secret(self, secret_name: str, secret_value: str):
        """
        处理接收到的秘密

        Args:
            secret_name: 秘密名称
            secret_value: Base64 编码的秘密值
        """
        try:
            secret_bytes = base64.b64decode(secret_value)

            if secret_name == SECRET_MEGOLM_BACKUP_V1:
                # 保存备份密钥
                if self._key_backup:
                    if self._key_backup.use_recovery_key_bytes(
                        secret_bytes, persist=True
                    ):
                        logger.info("[E2EE-Secrets] 已保存接收到的备份密钥")
                        # 仅在本账户缺失房间密钥时恢复
                        if self._key_backup.should_restore_for_session():
                            await self._key_backup.restore_room_keys_if_needed(
                                reason="secret_send"
                            )
                    else:
                        logger.warning("[E2EE-Secrets] 接收到的备份密钥格式无效")

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                # 保存主交叉签名密钥
                if self._cross_signing:
                    self._cross_signing.master_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的主签名密钥")

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                # 保存自签名密钥
                if self._cross_signing:
                    self._cross_signing.self_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的自签名密钥")
                    await self.publish_trusted_device(self.user_id, self.device_id)

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                # 保存用户签名密钥
                if self._cross_signing:
                    self._cross_signing.user_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的用户签名密钥")

            else:
                logger.warning(f"[E2EE-Secrets] 未知的秘密类型：{secret_name}")

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 处理接收的秘密失败：{e}")
