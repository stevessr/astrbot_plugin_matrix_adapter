"""In-room SAS accept negotiation and commitment construction."""

from astrbot.api import logger

from ......constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
)
from ....constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
)


class SASVerificationSendRoomAcceptCoreMixin:
    """协商房间内 SAS 算法并构造 accept 消息。"""

    async def _send_in_room_accept(
        self, room_id: str, transaction_id: str, start_content: dict
    ):
        """发送房间内 accept"""
        their_key_agreement = self._normalize_algorithm_values(
            start_content.get("key_agreement_protocols", [])
        )
        their_hashes = self._normalize_algorithm_values(start_content.get("hashes", []))
        their_macs = self._normalize_algorithm_values(
            start_content.get("message_authentication_codes", [])
        )
        their_sas = self._normalize_algorithm_values(
            start_content.get("short_authentication_string", [])
        )

        key_agreement = self._pick_algorithm(
            KEY_AGREEMENT_PROTOCOLS,
            their_key_agreement,
            fallback="curve25519-hkdf-sha256",
        )
        hash_algo = self._pick_algorithm(HASHES, their_hashes, fallback="sha256")
        mac = self._pick_algorithm(
            MESSAGE_AUTHENTICATION_CODES,
            their_macs,
            fallback="hkdf-hmac-sha256.v2",
        )
        sas_methods = [s for s in SHORT_AUTHENTICATION_STRING if s in their_sas]
        if not sas_methods:
            sas_methods = list(SHORT_AUTHENTICATION_STRING)

        session = self._sessions.get(transaction_id, {})

        our_public_key = await self._resolve_room_accept_public_key(session)

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        commitment = self._compute_room_accept_commitment(our_public_key, start_content)

        content = {
            "method": "m.sas.v1",
            "key_agreement_protocol": key_agreement,
            "hash": hash_algo,
            "message_authentication_code": mac,
            "short_authentication_string": sas_methods,
            "commitment": commitment,
        }

        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_ACCEPT, content, transaction_id
        )
        logger.info(
            f"[E2EE-Verify] 已发送房间内 accept (commitment: {(commitment or '')[:16]}...)"
        )
