"""SAS public-key message construction."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_KEY
from .compat import _vodozemac_sas_available


class SASVerificationHandshakeKeyMixin:
    """构造 SAS 公钥消息。"""

    async def _send_key(self, to_user: str, to_device: str, transaction_id: str):
        """发送由真实 SAS 会话生成的 ephemeral 公钥。"""
        session = self._sessions.get(transaction_id, {})

        our_public_key = session.get("our_public_key")
        if not isinstance(our_public_key, str) or not our_public_key:
            sas = session.get("sas")
            if sas and _vodozemac_sas_available():
                try:
                    our_public_key = sas.public_key.to_base64()
                except Exception as exc:
                    logger.error(f"[E2EE-Verify] 无法读取 SAS 公钥：{exc}")
                    our_public_key = None

        if not isinstance(our_public_key, str) or not our_public_key:
            logger.warning("[E2EE-Verify] 缺少真实 SAS ephemeral key，拒绝发送 key")
            cancel_bound = getattr(self, "_cancel_bound_verification_session", None)
            if callable(cancel_bound) and isinstance(session, dict) and session:
                await cancel_bound(
                    session,
                    transaction_id,
                    "m.unknown_method",
                    "SAS cryptographic state is unavailable",
                    sender=to_user,
                    from_device=to_device,
                )
            else:
                if isinstance(session, dict):
                    session["state"] = "cancelled"
                    session["cancel_code"] = "m.unknown_method"
                send_cancel = getattr(self, "_send_cancel", None)
                if callable(send_cancel):
                    await send_cancel(
                        to_user,
                        to_device,
                        transaction_id,
                        "m.unknown_method",
                        "SAS cryptographic state is unavailable",
                    )
            return

        session["our_public_key"] = our_public_key

        content = {
            "transaction_id": transaction_id,
            "key": our_public_key,
        }

        await self._send_to_device(M_KEY_VERIFICATION_KEY, to_user, to_device, content)
        session["key_sent"] = True
        logger.info(f"[E2EE-Verify] 已发送 key: {(our_public_key or '')[:20]}...")
