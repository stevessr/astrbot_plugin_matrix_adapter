"""In-room SAS ready message construction."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_READY


class SASVerificationSendRoomReadyMixin:
    """构造房间内 SAS ready 消息。"""

    async def _send_in_room_ready(self, room_id: str, transaction_id: str):
        """发送房间内 ready 响应"""
        session = self._sessions.get(transaction_id, {})
        content = {
            "from_device": self.device_id,
            "methods": self._get_supported_verification_methods(session.get("sender")),
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_READY, content, transaction_id
        )
        session["ready_sent"] = True
        logger.info("[E2EE-Verify] 已发送 ready")
