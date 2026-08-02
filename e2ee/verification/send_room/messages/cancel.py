"""In-room SAS cancellation message construction."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_CANCEL


class SASVerificationSendRoomCancelMixin:
    """构造房间内 SAS cancel 消息。"""

    async def _send_in_room_cancel(
        self, room_id: str, transaction_id: str, code: str, reason: str
    ):
        """发送房间内取消"""
        content = {
            "code": code,
            "reason": reason,
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_CANCEL, content, transaction_id
        )
        logger.info(f"[E2EE-Verify] 已发送房间内 cancel: {code} - {reason}")
