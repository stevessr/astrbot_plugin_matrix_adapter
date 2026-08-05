"""Dehydrated-device data resolution."""

from astrbot.api import logger


class KeyBackupSSSSStorageDeviceDataMixin:
    """Resolve the usable device data from a dehydrated-device event."""

    def _resolve_dehydrated_device_data(
        self, dehydrated_device: dict | None
    ) -> dict | None:
        if not dehydrated_device:
            logger.info("No dehydrated device event found")
            return None

        logger.info(f"Found dehydrated device event: {dehydrated_device.keys()}")
        device_data = dehydrated_device.get("device_data")
        if not isinstance(device_data, dict):
            device_data = (
                dehydrated_device if isinstance(dehydrated_device, dict) else {}
            )

        if not device_data:
            logger.warning(
                "Dehydrated device event does not contain usable device data"
            )
            return None

        logger.info(f"Dehydrated device data keys: {device_data.keys()}")
        return device_data


__all__ = ["KeyBackupSSSSStorageDeviceDataMixin"]
