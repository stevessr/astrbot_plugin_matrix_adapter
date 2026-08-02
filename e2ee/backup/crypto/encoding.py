"""Backup encoding and public-key parsing helpers."""

import base64

from astrbot.api import logger

from ....constants import CRYPTO_KEY_SIZE_32


class KeyBackupCryptoEncodingMixin:
    """解析无填充 base64 与备份版本公钥。"""

    @staticmethod
    def _decode_unpadded_base64(data: str) -> bytes:
        padding = (-len(data)) % 4
        if padding:
            data += "=" * padding
        try:
            return base64.b64decode(data)
        except Exception:
            return base64.urlsafe_b64decode(data)

    def _get_backup_public_key_bytes(self) -> bytes | None:
        backup_auth_data = getattr(self, "_backup_auth_data", None)
        public_key = backup_auth_data.get("public_key") if backup_auth_data else None
        if not public_key:
            return None

        try:
            key_bytes = self._decode_unpadded_base64(public_key)
        except Exception as e:
            logger.warning(f"解析备份公钥失败：{e}")
            return None

        if len(key_bytes) != CRYPTO_KEY_SIZE_32:
            logger.warning(
                f"备份公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(key_bytes)} 字节"
            )
            return None
        return key_bytes
