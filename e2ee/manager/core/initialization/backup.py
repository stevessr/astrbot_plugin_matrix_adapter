from astrbot.api import logger


class E2EEManagerCoreInitializationBackupMixin:
    async def _apply_key_backup_preference(self) -> None:
        """Resolve the Matrix v1.19 account-wide key-backup preference.

        An existing account preference enables backup on this headless client.
        An explicit local enablement is treated as the user's latest choice and
        is persisted for other clients. We deliberately do not write ``false``
        merely because the adapter's opt-in config uses its default value.
        """
        getter = getattr(self.client, "get_key_backup_preference", None)
        setter = getattr(self.client, "set_key_backup_preference", None)
        if not callable(getter):
            return

        try:
            preference = await getter()
        except Exception as e:
            logger.debug(f"读取 m.key_backup 偏好失败，沿用本地配置：{e}")
            return

        if preference is True and not self.enable_key_backup:
            self.enable_key_backup = True
            logger.info("已根据账户 m.key_backup 偏好启用密钥备份")
            return

        if self.enable_key_backup and preference is not True and callable(setter):
            try:
                await setter(True)
                logger.info("已同步账户 m.key_backup 偏好：enabled=true")
            except Exception as e:
                logger.warning(f"同步 m.key_backup 偏好失败：{e}")
