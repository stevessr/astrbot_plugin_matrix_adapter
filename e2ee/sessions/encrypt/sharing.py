"""Megolm outbound-session creation and key distribution."""

from astrbot.api import logger


class E2EEManagerSessionEncryptSharingMixin:
    async def _create_and_share_session(
        self,
        room_id: str,
        *,
        shared_history: bool = False,
    ):
        """创建 Megolm 出站会话并分发密钥"""
        if not self._olm:
            return

        # 创建会话
        session_id, session_key = self._olm.create_megolm_outbound_session(
            room_id,
            shared_history=shared_history,
        )
        logger.info(f"为房间 {room_id} 创建了 Megolm 会话")

        # 获取房间成员
        try:
            members = await self._get_room_members(room_id, force_refresh=True)
            if members:
                await self.ensure_room_keys_sent(
                    room_id,
                    members,
                    session_id,
                    session_key,
                    reason="new_session",
                    shared_history=shared_history,
                )
        except Exception as e:
            logger.error(f"分发密钥失败：{e}")
