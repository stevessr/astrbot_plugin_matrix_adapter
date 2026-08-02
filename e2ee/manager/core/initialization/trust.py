from astrbot.api import logger


class E2EEManagerCoreInitializationTrustMixin:
    async def _finalize_own_device_trust(self, log_prefix: str) -> None:
        if not self._cross_signing or not self._cross_signing.has_master_key:
            return

        device_signed = await self._cross_signing.sign_device(self.device_id)
        master_signed = await self._cross_signing.sign_master_key_with_device(
            self.user_id
        )
        if device_signed and master_signed:
            logger.info(f"{log_prefix}：{self._mask_device_id(self.device_id)}")
            return

        logger.warning(
            "自动签名设备未完全生效："
            f"device_signed={device_signed} master_signed={master_signed}"
        )
