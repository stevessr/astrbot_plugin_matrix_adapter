"""In-room SAS public-key message construction."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_KEY
from .compat import _vodozemac_sas_available


class SASVerificationSendRoomKeyMixin:
    """构造房间内 SAS 公钥消息。"""

    async def _send_in_room_key(self, room_id: str, transaction_id: str):
        """发送由真实 SAS 会话生成的房间内 ephemeral 公钥。"""
        session = self._sessions.get(transaction_id, {})

        our_public_key = session.get("our_public_key")
        if not isinstance(our_public_key, str) or not our_public_key:
            sas = session.get("sas")
            if sas and _vodozemac_sas_available():
                try:
                    our_public_key = sas.public_key.to_base64()
                except Exception as exc:
                    logger.error(f"[E2EE-Verify] 无法读取房间内 SAS 公钥：{exc}")
                    our_public_key = None

        if not isinstance(our_public_key, str) or not our_public_key:
            logger.warning("[E2EE-Verify] 缺少真实房间内 SAS ephemeral key，拒绝发送 key")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "SAS cryptographic state is unavailable",
            )
            return

        session["our_public_key"] = our_public_key
        content = {"key": our_public_key}

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_KEY, content, transaction_id
        )
        session["key_sent"] = True
        logger.info("[E2EE-Verify] 已发送 key")
