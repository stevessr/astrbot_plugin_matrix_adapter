"""Automatic key-backup upload for imported room keys."""

from astrbot.api import logger


class E2EEManagerDecryptRoomKeyBackupMixin:
    """Upload newly received keys to the key backup."""

    async def _backup_room_key(
        self,
        room_id,
        session_id,
        session_key,
        original_sender_key,
        claimed_keys,
        stored_forwarding_chain,
        shared_history,
    ):
        if self._key_backup and self.enable_key_backup:
            try:
                await self._key_backup.upload_single_key(
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
                    sender_key=original_sender_key,
                    sender_claimed_keys=claimed_keys,
                    forwarding_curve25519_key_chain=stored_forwarding_chain,
                    shared_history=shared_history,
                )
            except Exception as e:
                logger.warning(f"自动备份密钥失败：{e}")


__all__ = ["E2EEManagerDecryptRoomKeyBackupMixin"]
