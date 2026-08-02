"""In-room SAS completion message construction."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_DONE


class SASVerificationSendRoomDoneMixin:
    """构造房间内 SAS done 消息。"""

    async def _send_in_room_done(self, room_id: str, transaction_id: str):
        """发送房间内 done"""
        content = {}
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_DONE, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 done")
