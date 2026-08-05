"""Room-session restoration orchestration."""

from astrbot.api import logger


class KeyBackupRoomKeysRestoreOrchestratorMixin:
    """从密钥备份恢复房间会话。"""

    async def restore_room_keys(self, recovery_key: str | None = None) -> bool:
        """
        从备份恢复密钥

        Args:
            recovery_key: 恢复密钥 (覆盖初始化时的密钥)
        """
        if not self._backup_version:
            logger.warning("未发现备份，无法恢复")
            return False

        key_bytes = self._resolve_restore_key_bytes(recovery_key)
        if key_bytes is None:
            return False

        # 创建 PkDecryption 对象 (如果 vodozemac 可用)
        self._build_pk_decryption(key_bytes)

        try:
            restored, skipped = await self._restore_room_sessions(key_bytes)
            if restored > 0:
                logger.info(f"已恢复 {restored} 个会话密钥")
            if skipped > 0:
                logger.debug(f"跳过 {skipped} 个不兼容的会话")
            return restored > 0

        except Exception as e:
            logger.warning(f"恢复密钥失败：{e}")
            return False


__all__ = ["KeyBackupRoomKeysRestoreOrchestratorMixin"]
