"""Restore recovery-key resolution and verification."""

import time

from astrbot.api import logger

from ....crypto_utils import (
    _decode_recovery_key as _DEFAULT_DECODE_RECOVERY_KEY,
)
from ...compat import resolve_restore_symbol


class KeyBackupRoomKeysRestoreKeyMixin:
    """Resolve and verify the recovery key for a restore run."""

    def _resolve_restore_key_bytes(self, recovery_key: str | None) -> bytes | None:
        """Return verified recovery-key bytes or ``None`` when unavailable."""
        key_bytes = None
        if recovery_key:
            try:
                decode_recovery_key = resolve_restore_symbol(
                    "_decode_recovery_key", _DEFAULT_DECODE_RECOVERY_KEY
                )
                key_bytes = decode_recovery_key(recovery_key)
            except Exception as e:
                logger.error(f"解析恢复密钥失败：{e}")
                return None
        elif self._recovery_key_bytes:
            key_bytes = self._recovery_key_bytes
        else:
            logger.error("无恢复密钥，无法解密备份")
            return None

        self._last_restore_attempt_ts = time.monotonic()

        # 验证密钥是否匹配备份版本
        if not self._verify_recovery_key(key_bytes):
            return None

        # Keep using the verified key for subsequent runs.
        self.use_recovery_key_bytes(key_bytes, persist=True)
        return key_bytes


__all__ = ["KeyBackupRoomKeysRestoreKeyMixin"]
