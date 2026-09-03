"""In-room SAS start message construction."""

from astrbot.api import logger

from .....constants import (
    KEY_AGREEMENT_PROTOCOLS,
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


class SASVerificationSendRoomStartMixin:
    """Construct an in-room SAS start without crossing into to-device transport."""

    async def _send_in_room_start(self, room_id: str, transaction_id: str):
        session = self._sessions.get(transaction_id, {})
        if not _vodozemac_sas_available() or Sas is None:
            logger.warning("[E2EE-Verify] vodozemac 不可用，拒绝发送房间内 SAS start")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "SAS verification is unavailable on this client",
            )
            return

        try:
            sas = Sas()
            our_public_key = sas.public_key.to_base64()
        except Exception as e:
            logger.warning(f"[E2EE-Verify] Failed to create in-room SAS: {e}")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
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
        }
        await self._send_in_room_event(
            room_id,
            M_KEY_VERIFICATION_START,
            content,
            transaction_id,
        )

        # _send_in_room_event adds the m.reference relation in-place. Keep the
        # exact transmitted content for the peer commitment verification.
        session["start_content"] = dict(content)
        session["we_are_initiator"] = True
        session["start_sent"] = True
        session["state"] = "start_sent"
        logger.info("[E2EE-Verify] 已发送房间内 start")


__all__ = ["SASVerificationSendRoomStartMixin"]
