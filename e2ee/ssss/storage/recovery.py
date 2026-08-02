"""Dehydrated-device recovery helpers for secret storage."""

import json

from astrbot.api import logger

from ....constants import (
    CRYPTO_KEY_SIZE_32,
    DEHYDRATED_DEVICE_EVENT,
    MSC2697_DEHYDRATED_DEVICE_EVENT,
)
from ...backup.crypto_utils import _decode_recovery_key


class KeyBackupSSSSStorageRecoveryMixin:
    """从 dehydrated device account data 恢复房间备份密钥。"""

    def _get_valid_local_recovery_key_bytes(self) -> bytes | None:
        verify = getattr(self, "_verify_recovery_key", None)

        current_key = getattr(self, "_recovery_key_bytes", None)
        if (
            isinstance(current_key, (bytes, bytearray))
            and len(current_key) == CRYPTO_KEY_SIZE_32
        ):
            key_bytes = bytes(current_key)
            if not callable(verify):
                return key_bytes
            try:
                if verify(key_bytes, log_mismatch=False):
                    return key_bytes
            except TypeError:
                if verify(key_bytes):
                    return key_bytes

        load_extracted_key = getattr(self, "_load_extracted_key", None)
        if not callable(load_extracted_key):
            return None

        extracted_key = load_extracted_key()
        if not isinstance(extracted_key, (bytes, bytearray)):
            return None
        if len(extracted_key) != CRYPTO_KEY_SIZE_32:
            return None

        key_bytes = bytes(extracted_key)
        if not callable(verify):
            return key_bytes
        try:
            if verify(key_bytes, log_mismatch=False):
                return key_bytes
        except TypeError:
            if verify(key_bytes):
                return key_bytes
        return None

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

    def _extract_backup_key_from_dehydrated_device(
        self, provided_key_bytes: bytes, dehydrated_device: dict | None
    ) -> bytes | None:
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

        try:
            try:
                device_info = json.loads(decrypted_device)
                logger.info(
                    f"Decrypted Dehydrated Device Info keys: {device_info.keys()}"
                )

                backup_key = None
                if "m.megolm_backup.v1" in device_info:
                    backup_key = device_info["m.megolm_backup.v1"]
                    logger.info(
                        "Found backup key in dehydrated device: m.megolm_backup.v1"
                    )
                elif "backup_key" in device_info:
                    backup_key = device_info["backup_key"]
                    logger.info("Found backup key in dehydrated device: backup_key")
                elif "recovery_key" in device_info:
                    backup_key = device_info["recovery_key"]
                    logger.info("Found backup key in dehydrated device: recovery_key")

                if backup_key:
                    if isinstance(backup_key, str):
                        try:
                            extracted_key = _decode_recovery_key(backup_key)
                            logger.info(
                                "✅ Extracted backup key from dehydrated device "
                                f"({len(extracted_key)} bytes)"
                            )
                            return extracted_key
                        except Exception:
                            logger.warning("Failed to decode backup key from device")
                    elif isinstance(backup_key, bytes):
                        if len(backup_key) == CRYPTO_KEY_SIZE_32:
                            logger.info(
                                "✅ Extracted backup key from dehydrated device "
                                f"({len(backup_key)} bytes)"
                            )
                            return backup_key

            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                logger.info(
                    "Decrypted Dehydrated Device data is not JSON "
                    f"(len: {len(decrypted_device)})"
                )
                if len(decrypted_device) == CRYPTO_KEY_SIZE_32:
                    logger.info(
                        "✅ Dehydrated device data is exactly 32 bytes, using as backup key"
                    )
                    return decrypted_device
        except Exception as e:
            logger.warning(f"Failed to extract backup key from dehydrated device: {e}")

        return None
