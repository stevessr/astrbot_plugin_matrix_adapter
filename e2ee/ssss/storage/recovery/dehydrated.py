"""Dehydrated-device event lookup and recovery orchestration."""

from astrbot.api import logger

from .....constants import DEHYDRATED_DEVICE_EVENT, MSC2697_DEHYDRATED_DEVICE_EVENT


class KeyBackupSSSSStorageDehydratedMixin:
    async def _get_dehydrated_device(self) -> dict | None:
        dehydrated_device = await self.client.get_global_account_data(
            DEHYDRATED_DEVICE_EVENT
        )
        if dehydrated_device:
            logger.info("Found stable dehydrated device event")
            return dehydrated_device

        dehydrated_device = await self.client.get_global_account_data(
            MSC2697_DEHYDRATED_DEVICE_EVENT
        )
        if dehydrated_device:
            logger.info("Found MSC2697 dehydrated device event")

        return dehydrated_device

    async def _try_restore_from_dehydrated_device_key(
        self, provided_key_bytes: bytes
    ) -> bytes | None:
        if not provided_key_bytes:
            return None

        dehydrated_device = await self._get_dehydrated_device()
        return self._extract_backup_key_from_dehydrated_device(
            provided_key_bytes,
            dehydrated_device,
        )
