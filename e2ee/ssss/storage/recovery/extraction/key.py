"""Backup-key extraction from decrypted device info."""

import json

from astrbot.api import logger

from ......constants import CRYPTO_KEY_SIZE_32
from .....backup.crypto_utils import _decode_recovery_key


class KeyBackupSSSSStorageKeyExtractMixin:
    """Extract the backup key from decrypted dehydrated-device data."""

    def _extract_key_from_dehydrated_info(
        self, decrypted_device: bytes
    ) -> bytes | None:
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


__all__ = ["KeyBackupSSSSStorageKeyExtractMixin"]
