"""Dehydrated-device data decryption."""

from astrbot.api import logger

from ......constants import (
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
)


class KeyBackupSSSSStorageDecryptDeviceMixin:
    """Decrypt the dehydrated-device data with the provided key."""

    def _decrypt_dehydrated_device(
        self, provided_key_bytes: bytes, device_data: dict
    ) -> bytes | None:
        decrypted_device = None
        for secret_name in (
            DEHYDRATED_DEVICE_EVENT,
            MSC2697_DEHYDRATED_DEVICE_EVENT,
        ):
            decrypted_device = self._decrypt_ssss_data(
                provided_key_bytes,
                device_data,
                secret_name=secret_name,
            )
            if decrypted_device:
                logger.info(
                    "✅ Successfully decrypted Dehydrated Device data "
                    f"with secret name {secret_name}!"
                )
                break

        if not decrypted_device:
            logger.warning("Failed to decrypt Dehydrated Device with provided key")
            return None
        return decrypted_device


__all__ = ["KeyBackupSSSSStorageDecryptDeviceMixin"]
