"""Validation of Secret Storage key metadata and MACs."""

from astrbot.api import logger

from .....constants import CRYPTO_KEY_SIZE_32
from ....verification.crypto_utils import _decode_base64


class KeyBackupSSSSStorageContextValidationMixin:
    def _secret_storage_key_matches(self, key: bytes, key_data: dict | None) -> bool:
        if not key or len(key) != CRYPTO_KEY_SIZE_32:
            return False
        if not isinstance(key_data, dict) or not key_data:
            return True

        algorithm = key_data.get("algorithm")
        if algorithm and algorithm != self._SSSS_ALGORITHM:
            logger.warning(f"不支持的 Secret Storage 算法：{algorithm}")
            return False

        iv_b64 = key_data.get("iv")
        mac_b64 = key_data.get("mac")
        if not iv_b64 or not mac_b64:
            return True

        try:
            encrypted = self._encrypt_ssss_data(
                key,
                b"\x00" * CRYPTO_KEY_SIZE_32,
                secret_name="",
                iv=_decode_base64(iv_b64),
            )
            expected_mac = _decode_base64(mac_b64)
            actual_mac = _decode_base64(encrypted["mac"])
            return actual_mac == expected_mac
        except Exception as e:
            logger.warning(f"验证 Secret Storage Key 失败：{e}")
            return False
