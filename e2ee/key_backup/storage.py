"""Persistence helpers for extracted backup keys."""

from pathlib import Path

from astrbot.api import logger

from ...constants import CRYPTO_KEY_SIZE_32


class KeyBackupStorageMixin:
    def _get_extracted_key_path(self) -> str:
        """获取提取的备份密钥存储路径"""
        if self.store_path:
            return str(Path(self.store_path) / "extracted_backup_key.bin")
        return ""

    def _save_extracted_key(self, key_bytes: bytes):
        """保存从 SSSS 提取的备份密钥到本地"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return

            Path(path).parent.mkdir(parents=True, exist_ok=True)

            with open(path, "wb") as f:
                f.write(key_bytes)

            logger.info(f"已保存提取的备份密钥到 {path}")
        except Exception as e:
            logger.warning(f"保存提取的备份密钥失败：{e}")

    def _load_extracted_key(self) -> bytes | None:
        """从本地加载之前提取的备份密钥"""
        try:
            path = self._get_extracted_key_path()
            if not path:
                return None

            if not Path(path).exists():
                return None

            with open(path, "rb") as f:
                key_bytes = f.read()

            if len(key_bytes) == CRYPTO_KEY_SIZE_32:
                logger.info("从本地加载了提取的备份密钥")
                return key_bytes
            else:
                logger.warning(f"本地备份密钥长度不正确：{len(key_bytes)} bytes")
                return None
        except Exception as e:
            logger.debug(f"加载提取的备份密钥失败：{e}")
            return None
