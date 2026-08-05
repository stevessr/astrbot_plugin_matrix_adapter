"""Room-key sharing entry orchestration and per-session locking."""

import asyncio


class E2EEManagerSessionShareKeysShareOrchestratorMixin:
    """为选定成员准备并锁定房间密钥分发。"""

    async def ensure_room_keys_sent(
        self,
        room_id: str,
        members: list[str],
        session_id: str | None = None,
        session_key: str | None = None,
        target_users: list[str] | None = None,
        reason: str = "sync",
        shared_history: bool | None = None,
    ) -> int:
        """
        确保房间密钥已发送给所有成员的设备

        Args:
            room_id: 房间 ID
            members: 成员用户 ID 列表
            session_id: 可选，指定会话 ID
            session_key: 可选，指定会话密钥
            target_users: 可选，只分发给指定用户（其余成员跳过）
            reason: 日志用途，标记分发触发原因
            shared_history: MSC4268 会话是否允许与未来成员共享

        Returns:
            Number of devices that received the room key successfully.
        """
        if not self._olm or not members:
            return 0

        normalized_members = self._normalize_share_members(members, target_users)
        if normalized_members is None:
            return 0

        resolved = self._resolve_share_session(room_id, session_id, session_key)
        if resolved is None:
            return 0
        session_id, session_key = resolved

        locks = getattr(self, "_room_key_share_locks", None)
        if not isinstance(locks, dict):
            locks = {}
            self._room_key_share_locks = locks
        lock = locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            return await self._ensure_room_keys_sent_locked(
                room_id=room_id,
                members=normalized_members,
                session_id=session_id,
                session_key=session_key,
                reason=reason,
                shared_history=shared_history,
            )


__all__ = ["E2EEManagerSessionShareKeysShareOrchestratorMixin"]
