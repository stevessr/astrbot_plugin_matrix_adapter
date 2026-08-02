"""Backup recovery initialization operations."""

from astrbot.api import logger


class KeyBackupRestoreInitializationMixin:
    """初始化密钥备份恢复状态。"""

    async def initialize(self):
        """初始化密钥备份"""
        try:
            version = await self._get_current_backup_version()
            if version:
                self._backup_version = version
                # 1) Prefer already-verified local backup key material.
                local_key = self._get_valid_local_recovery_key_bytes()
                if local_key:
                    if self.use_recovery_key_bytes(local_key):
                        logger.info("✅ 使用本地保存的提取密钥成功验证！")
                        return

                # 2) Treat configured key as dehydrated/backup recovery material first,
                # then fall back to Secret Storage compatibility.
                provided_key = getattr(
                    self,
                    "_provided_recovery_material_bytes",
                    self._provided_secret_storage_key_bytes,
                )
                if provided_key:
                    real_key = await self._try_restore_from_dehydrated_device_key(
                        provided_key
                    )
                    if real_key and self._verify_recovery_key(
                        real_key, log_mismatch=False
                    ):
                        if self.use_recovery_key_bytes(real_key, persist=True):
                            logger.info(
                                "✅ 已通过配置密钥解出 dehydrated device 中的备份密钥"
                            )
                            return

                    # 3) Fallback: configured key is direct backup key.
                    if self._verify_recovery_key(provided_key, log_mismatch=False):
                        if self.use_recovery_key_bytes(provided_key):
                            logger.info("✅ 提供密钥可直接作为备份恢复密钥")
                            return

                    # 4) Compatibility fallback: configured key may still be a Secret Storage key.
                    real_key = await self._try_restore_from_secret_storage(
                        provided_key,
                        include_dehydrated=False,
                        allow_local_short_circuit=False,
                    )
                    if real_key and self._verify_recovery_key(
                        real_key, log_mismatch=False
                    ):
                        if self.use_recovery_key_bytes(real_key, persist=True):
                            logger.info(
                                "✅ 已通过配置密钥兼容解出 Secret Storage 中的备份密钥"
                            )
                            return
                    logger.warning(
                        "配置密钥未能匹配当前备份，等待后续 secret.send/手动更新"
                    )
                elif self._recovery_key_bytes and self._verify_recovery_key(
                    self._recovery_key_bytes, log_mismatch=False
                ):
                    self.use_recovery_key_bytes(self._recovery_key_bytes)
            else:
                logger.info("未发现密钥备份")
        except Exception as e:
            logger.warning(f"初始化失败：{e}")
