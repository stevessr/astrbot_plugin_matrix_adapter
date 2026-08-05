"""Key-backup single-key upload guards."""

from astrbot.api import logger

from .....constants import MEGOLM_ALGO


class KeyBackupUploadSessionGuardMixin:
    """Validate whether a single session key may be uploaded."""

    def _check_upload_guard(self, algorithm: str) -> bool:
        """Return ``True`` when the upload may proceed."""
        if not self._backup_version:
            return False
        if algorithm != MEGOLM_ALGO:
            logger.warning(f"[KeyBackup] 不支持的会话算法：{algorithm}")
            return False
        return True


__all__ = ["KeyBackupUploadSessionGuardMixin"]
