"""E2EE manager startup orchestration."""

from astrbot.api import logger

from ...compat import vodozemac_available


class E2EEManagerCoreInitializationStartupCoreMixin:
    async def initialize(self):
        """初始化 E2EE 组件"""
        if not vodozemac_available():
            logger.warning("vodozemac 未安装，E2EE 功能不可用")
            return False

        try:
            await self._init_olm_components()
            await self._init_verification()
            await self._init_key_backup_signing()
            await self._init_own_device_trust()

            self._initialized = True
            logger.info(
                f"E2EE 初始化成功 (device_id: {self._mask_device_id(self.device_id)})"
            )

            await self._post_initialization_checks()
            return True

        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
            return False
