"""Room-key request response orchestration."""

from astrbot.api import logger

from ....constants import WITHHELD_UNAVAILABLE


class E2EEManagerRequestsRespondCoreMixin:
    """Respond to room-key requests from verified devices."""

    async def respond_to_key_request(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
    ) -> bool:
        """
        响应来自其他设备的密钥请求

        只有同一用户的已验证设备才会收到响应。

        Args:
            sender: 请求者用户 ID
            requesting_device_id: 请求者设备 ID
            room_id: 房间 ID
            session_id: 会话 ID

        Returns:
            Whether the requested session was forwarded successfully.
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            logger.warning("未初始化，无法响应密钥请求")
            return False
        if not all(
            isinstance(value, str) and value
            for value in (sender, requesting_device_id, room_id, session_id)
        ):
            return False

        try:
            # 只响应同一用户的请求（安全限制），并验证请求者设备密钥
            verified = await self._verify_requester(
                sender,
                requesting_device_id,
                room_id,
                session_id,
            )
            if verified is None:
                return False
            device_info, resp = verified

            # 获取并导出请求的 Megolm 会话
            exported_key = await self._export_session(
                sender,
                requesting_device_id,
                room_id,
                session_id,
            )
            if exported_key is None:
                return False

            # 验证会话来源元数据，防止无认证来源的密钥被转发
            provenance = await self._load_provenance(
                sender,
                requesting_device_id,
                room_id,
                session_id,
            )
            if provenance is None:
                return False
            (
                original_sender_key,
                original_ed25519,
                forwarding_chain,
                metadata,
            ) = provenance

            return await self._forward_session(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                exported_key,
                original_sender_key,
                original_ed25519,
                forwarding_chain,
                metadata,
            )

        except Exception as e:
            logger.warning(f"响应密钥请求失败：{e}")
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The room-key request could not be processed",
            )
            return False
