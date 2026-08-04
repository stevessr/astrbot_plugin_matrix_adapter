"""Room-message encryption and rotation orchestration."""

from astrbot.api import logger


class E2EEManagerSessionEncryptMessageCoreMixin:
    async def encrypt_message(
        self, room_id: str, event_type: str, content: dict
    ) -> dict | None:
        """
        加密消息

        Args:
            room_id: 房间 ID
            event_type: 事件类型
            content: 事件内容

        Returns:
            加密后的 m.room.encrypted 内容，或 None
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            logger.warning("E2EE 未初始化，无法加密")
            return None

        try:
            encryption_configs = getattr(self, "_room_encryption_config", {})
            if not isinstance(encryption_configs, dict) or room_id not in (
                encryption_configs
            ):
                # The state scan also caches custom Megolm rotation limits.
                await self._get_room_members(room_id)
            shared_history = await self._get_room_shared_history(room_id)

            # 检查是否有出站会话
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            session_info = await self._check_outbound_session_rotation(
                room_id,
                session_info,
                shared_history,
            )
            if not session_info:
                # 创建新会话并分发密钥
                await self._create_and_share_session(
                    room_id,
                    shared_history=shared_history,
                )
            else:
                # 会话已存在，确保密钥已分发给所有成员
                session_id, session_key = session_info
                members = await self._get_room_members(room_id)
                if members:
                    await self.ensure_room_keys_sent(
                        room_id,
                        members,
                        session_id,
                        session_key,
                        reason="send_message",
                        shared_history=shared_history,
                    )

            # 加密消息
            return self._olm.encrypt_megolm(room_id, event_type, content)

        except Exception as e:
            logger.error(f"加密消息失败：{e}")
            return None
