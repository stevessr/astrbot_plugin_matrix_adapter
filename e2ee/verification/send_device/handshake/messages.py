"""SAS ready and start message construction."""

from astrbot.api import logger

from .....constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_START,
    M_SAS_V1_METHOD,
)
from ...constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
    Sas,
)
from .compat import _vodozemac_sas_available


class SASVerificationHandshakeMessagesMixin:
    """构造 SAS ready 与 start 握手消息。"""

    async def _send_ready(self, to_user: str, to_device: str, transaction_id: str):
        """发送 ready 响应"""
        content = {
            "from_device": self.device_id,
            "methods": self._get_supported_verification_methods(to_user),
            "transaction_id": transaction_id,
        }
        await self._send_to_device(
            M_KEY_VERIFICATION_READY, to_user, to_device, content
        )
        session = self._sessions.get(transaction_id)
        if isinstance(session, dict):
            session["ready_sent"] = True
        logger.info("[E2EE-Verify] 已发送 ready")

    async def _abort_unavailable_sas_start(
        self,
        session: dict,
        to_user: str,
        to_device: str,
        transaction_id: str,
        reason: str,
    ) -> None:
        cancel_bound = getattr(self, "_cancel_bound_verification_session", None)
        if callable(cancel_bound):
            await cancel_bound(
                session,
                transaction_id,
                "m.unknown_method",
                reason,
                sender=to_user,
                from_device=to_device,
            )
            return

        session["state"] = "cancelled"
        session["cancel_code"] = "m.unknown_method"
        send_cancel = getattr(self, "_send_cancel", None)
        if callable(send_cancel):
            await send_cancel(
                to_user,
                to_device,
                transaction_id,
                "m.unknown_method",
                reason,
            )

    async def _send_start(self, to_user: str, to_device: str, transaction_id: str):
        """发送 start 消息 (作为发起者)。"""
        session = self._sessions.get(transaction_id, {})
        if not _vodozemac_sas_available() or Sas is None:
            logger.warning("[E2EE-Verify] vodozemac 不可用，拒绝发送 SAS start")
            await self._abort_unavailable_sas_start(
                session,
                to_user,
                to_device,
                transaction_id,
                "SAS verification is unavailable on this client",
            )
            return

        try:
            sas = Sas()
            our_public_key = sas.public_key.to_base64()
        except Exception as e:
            logger.warning(f"[E2EE-Verify] Failed to create SAS: {e}")
            await self._abort_unavailable_sas_start(
                session,
                to_user,
                to_device,
                transaction_id,
                "Unable to initialize SAS verification",
            )
            return

        session["sas"] = sas
        session["our_public_key"] = our_public_key

        content = {
            "from_device": self.device_id,
            "method": M_SAS_V1_METHOD,
            "key_agreement_protocols": KEY_AGREEMENT_PROTOCOLS,
            "hashes": HASHES,
            "message_authentication_codes": MESSAGE_AUTHENTICATION_CODES,
            "short_authentication_string": SHORT_AUTHENTICATION_STRING,
            "transaction_id": transaction_id,
        }
        session["start_content"] = dict(content)
        session["we_are_initiator"] = True

        await self._send_to_device(
            M_KEY_VERIFICATION_START, to_user, to_device, content
        )
        session["start_sent"] = True
        session["state"] = "start_sent"
        logger.info("[E2EE-Verify] 已发送 start")
