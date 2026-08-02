"""Room-key sharing entry points and per-session locking."""

import asyncio

from astrbot.api import logger


class E2EEManagerSessionShareKeysEntryMixin:
    """为选定成员准备并锁定房间密钥分发。"""

    async def _share_existing_room_key(
        self,
        room_id: str,
        target_users: list[str] | None = None,
        reason: str = "proactive",
        force_members_refresh: bool = False,
    ) -> None:
        """Share an existing outbound Megolm session key to selected users."""
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        session_info = self._olm.get_megolm_outbound_session_info(room_id)
        if not session_info:
            return
        session_id, session_key = session_info

        members = await self._get_room_members(
            room_id, force_refresh=force_members_refresh
        )

        if not members:
            return

        await self.ensure_room_keys_sent(
            room_id=room_id,
            members=members,
            session_id=session_id,
            session_key=session_key,
            target_users=target_users,
            reason=reason,
        )

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

        normalized_members = list(
            dict.fromkeys(user_id for user_id in members if user_id)
        )
        if not normalized_members:
            return 0

        if target_users is not None:
            target_set = {
                user_id
                for user_id in target_users
                if user_id and isinstance(user_id, str)
            }
            if not target_set:
                return 0
            normalized_members = [
                user_id for user_id in normalized_members if user_id in target_set
            ]
            if not normalized_members:
                return 0

        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if not session_info:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return 0
            session_id, session_key = session_info

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
