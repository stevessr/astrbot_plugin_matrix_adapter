"""E2EE initialization stage of the Matrix adapter startup."""

from astrbot.api import logger


async def _startup_e2ee(self) -> None:
    if self.e2ee_manager:
        try:
            actual_device_id = self.client.device_id or self._matrix_config.device_id
            if actual_device_id != self.e2ee_manager.device_id:
                logger.info(
                    "更新 E2EE device_id："
                    f"{self._mask_device_id(self.e2ee_manager.device_id)} -> "
                    f"{self._mask_device_id(actual_device_id)}"
                )
                self.e2ee_manager.device_id = actual_device_id
                # 持久化服务器返回的 device_id
                self._matrix_config.set_device_id(actual_device_id)
            await self.e2ee_manager.initialize()
        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
