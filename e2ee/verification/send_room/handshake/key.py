"""In-room SAS public-key message construction."""

import base64
import secrets

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_KEY
from .compat import _vodozemac_sas_available


class SASVerificationSendRoomKeyMixin:
    """构造房间内 SAS 公钥消息。"""

    async def _send_in_room_key(self, room_id: str, transaction_id: str):
        """发送房间内公钥"""
        session = self._sessions.get(transaction_id, {})

        # 优先使用已存储的公钥（在 accept 中计算 commitment 时使用的同一个）
        our_public_key = session.get("our_public_key")
        if not our_public_key:
            sas = session.get("sas")
            if sas and _vodozemac_sas_available():
                our_public_key = sas.public_key.to_base64()
            else:
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
            session["our_public_key"] = our_public_key

        session["key_sent"] = True

        content = {
            "key": our_public_key,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_KEY, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 key")
