"""Read local secrets for device-to-device sharing."""

import base64

from astrbot.api import logger

from .....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)


class E2EEManagerSecretsSharingMixin:
    """读取本地可共享秘密。"""

    async def _get_secret_for_sharing(self, secret_name: str) -> str | None:
        """
        获取要共享的秘密值

        Args:
            secret_name: 秘密名称

        Returns:
            Base64 编码的秘密值，或 None
        """
        try:
            if secret_name == SECRET_MEGOLM_BACKUP_V1:
                # 获取备份密钥
                if self._key_backup:
                    key_bytes = self._key_backup.recovery_key_bytes
                    if not key_bytes:
                        key_bytes = self._key_backup.load_extracted_key()
                    if not key_bytes:
                        logger.debug("[E2EE-Secrets] 备份密钥不可用")
                        return None
                    return base64.b64encode(key_bytes).decode("utf-8")
                logger.debug("[E2EE-Secrets] 备份密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                # 获取主交叉签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.master_private_key is not None
                ):
                    key = self._cross_signing.master_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 主签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                # 获取自签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.self_signing_private_key is not None
                ):
                    key = self._cross_signing.self_signing_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 自签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                # 获取用户签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.user_signing_private_key is not None
                ):
                    key = self._cross_signing.user_signing_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 用户签名密钥不可用")
                return None

            else:
                logger.warning(f"[E2EE-Secrets] 未知的秘密类型：{secret_name}")
                return None

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 获取秘密失败：{e}")
            return None
