"""Requests for missing private secrets after same-user verification."""

from astrbot.api import logger

from ....constants import SECRET_MEGOLM_BACKUP_V1


class E2EEManagerVerificationSecretsMixin:
    """在同账号设备验证后恢复交叉签名和备份秘密。"""

    async def request_missing_secrets_after_verification(self, user_id: str) -> None:
        """After same-user verification, request any missing bootstrap secrets once."""
        if user_id != self.user_id:
            return

        cross_signing = getattr(self, "_cross_signing", None)
        if (
            cross_signing
            and hasattr(cross_signing, "_query_server_cross_signing_state")
            and hasattr(cross_signing, "_request_missing_private_keys_from_devices")
        ):
            try:
                (
                    server_master,
                    server_self_signing,
                    server_user_signing,
                    _keys_need_regen,
                ) = await cross_signing._query_server_cross_signing_state()
                await cross_signing._request_missing_private_keys_from_devices(
                    server_master,
                    server_self_signing,
                    server_user_signing,
                )
            except Exception as e:
                logger.debug(f"验证后请求缺失交叉签名私钥失败：{e}")

        key_backup = getattr(self, "_key_backup", None)
        if not key_backup or not getattr(key_backup, "backup_version", None):
            return

        try:
            local_backup_key = getattr(key_backup, "recovery_key_bytes", None)
            if not local_backup_key and hasattr(key_backup, "load_extracted_key"):
                local_backup_key = key_backup.load_extracted_key()
            if local_backup_key:
                return

            request_id = await self.request_secret_from_devices(SECRET_MEGOLM_BACKUP_V1)
            if request_id:
                logger.info("[E2EE-Secrets] 验证完成后已请求备份密钥")
        except Exception as e:
            logger.debug(f"验证后请求缺失备份密钥失败：{e}")


__all__ = ["E2EEManagerVerificationSecretsMixin"]
