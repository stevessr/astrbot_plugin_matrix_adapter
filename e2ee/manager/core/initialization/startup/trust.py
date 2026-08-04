"""Post-construction device trust and periodic task startup."""

from astrbot.api import logger


class E2EEManagerCoreInitializationStartupTrustMixin:
    async def _init_own_device_trust(self):
        """自动签名自己的设备（使设备变为"已验证"状态）。"""
        if self._cross_signing.has_master_key:
            await self._finalize_own_device_trust("已自动签名设备")
        else:
            # 如果没有交叉签名密钥，尝试上传
            try:
                await self._cross_signing.upload_cross_signing_keys()
                await self._finalize_own_device_trust("已上传交叉签名密钥并签名设备")
            except Exception as e:
                logger.warning(f"上传交叉签名密钥失败（可能需要 UIA）：{e}")

    async def _post_initialization_checks(self):
        """初始化完成后的验证与定期任务启动。"""
        # 初始化完成后，尝试为自己的未验证设备发起验证
        await self._verify_untrusted_own_devices()

        # 启动定期密钥分发检查任务
        if self.key_share_check_interval > 0:
            await self._start_key_share_check_task()
            logger.info(
                f"已启动定期密钥分发检查任务，间隔：{self.key_share_check_interval} 秒"
            )
        else:
            logger.info(
                "Room-key distribution is using lazy mode; keys will be "
                "rechecked on encrypted sends and device-list changes"
            )
