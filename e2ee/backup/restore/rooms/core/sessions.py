"""Room-session restoration loop."""

from astrbot.api import logger


class KeyBackupRoomKeysRestoreSessionsMixin:
    """Fetch and restore all backed-up room sessions."""

    async def _restore_room_sessions(self, key_bytes: bytes) -> tuple[int, int]:
        """Return ``(restored, skipped)`` counts for the fetched backup."""
        logger.info(f"开始从备份恢复密钥 (version={self._backup_version})")
        response = await self.client.get_room_keys(self._backup_version)

        rooms = response.get("rooms", {})
        total_sessions = sum(len(s) for s in rooms.values())
        logger.info(f"获取到 {len(rooms)} 个房间，共 {total_sessions} 个会话")

        restored = 0
        skipped = 0

        for room_id, room_data in rooms.items():
            # API 返回格式：rooms[room_id] = {"sessions": {session_id: {...}}}
            sessions = room_data.get("sessions", room_data)
            if not isinstance(sessions, dict):
                sessions = room_data  # 回退到直接使用 room_data
            for session_id, session_data in sessions.items():
                try:
                    restored_one = await self._restore_single_session(
                        room_id, session_id, session_data, key_bytes
                    )
                    if restored_one:
                        restored += 1
                    else:
                        skipped += 1
                except Exception as e:
                    logger.debug(f"恢复会话 {(session_id or '')[:8]}... 失败：{e}")
                    skipped += 1

        return restored, skipped


__all__ = ["KeyBackupRoomKeysRestoreSessionsMixin"]
