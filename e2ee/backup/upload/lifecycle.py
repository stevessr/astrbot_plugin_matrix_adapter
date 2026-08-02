"""Backup-version discovery and creation operations."""

import base64
import secrets

from astrbot.api import logger

from ....constants import (
    CRYPTO_KEY_SIZE_32,
    MEGOLM_BACKUP_ALGO,
)
from ..crypto_utils import (
    _compute_hkdf,
    _encode_recovery_key,
)


class KeyBackupUploadLifecycleMixin:
    """获取并创建 Matrix 密钥备份版本。"""

    async def _get_current_backup_version(self) -> str | None:
        """获取当前备份版本"""
        try:
            response = await self.client.get_key_backup_versions()
            version = response.get("version")
            if version:
                self._backup_auth_data = response.get("auth_data", {})
            return version
        except Exception:
            return None

    async def create_backup(self) -> tuple[str, str] | None:
        """
        创建新的密钥备份

        Returns:
            (version, recovery_key) 或 None
        """
        try:
            # 如果没有提供恢复密钥，生成新的
            if not self._recovery_key_bytes:
                self._recovery_key_bytes = secrets.token_bytes(CRYPTO_KEY_SIZE_32)
                self._encryption_key = _compute_hkdf(
                    self._recovery_key_bytes, b"", b"m.megolm_backup.v1"
                )
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)
                logger.warning("已生成新的恢复密钥。出于安全考虑，密钥不会写入日志。")
                logger.warning(
                    "请从安全输出通道复制返回值并配置到 matrix_e2ee_recovery_key。"
                )
            else:
                recovery_key_str = _encode_recovery_key(self._recovery_key_bytes)

            # 生成用于备份的公钥
            # 根据 Matrix 规范，使用 X25519 从私钥派生公钥
            # 参考：https://spec.matrix.org/latest/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import x25519

            private_key = x25519.X25519PrivateKey.from_private_bytes(
                self._recovery_key_bytes
            )
            public_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            # 使用 unpadded base64 编码
            public_key = base64.b64encode(public_key_bytes).decode().rstrip("=")

            # 创建备份
            response = await self.client.create_key_backup_version(
                {
                    "algorithm": MEGOLM_BACKUP_ALGO,
                    "auth_data": {
                        "public_key": public_key,
                    },
                }
            )

            version = response.get("version")
            if version:
                self._backup_version = version
                logger.info(f"创建备份成功：version={version}")
                return (version, recovery_key_str)

        except Exception as e:
            logger.error(f"创建备份失败：{e}")
        return None
