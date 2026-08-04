"""SAS accept negotiation and commitment construction."""

from astrbot.api import logger

from ......constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
    M_SAS_V1_METHOD,
)
from ....constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
)


class SASVerificationHandshakeNegotiationCoreMixin:
    """协商 SAS 算法并构造 accept 消息。"""

    async def _send_accept(
        self, to_user: str, to_device: str, transaction_id: str, start_content: dict
    ):
        """发送 accept - 使用真正的密钥协商"""
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

        our_public_key = await self._resolve_our_public_key(session)

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        commitment = self._compute_accept_commitment(our_public_key, start_content)

        content = {
            "transaction_id": transaction_id,
            "method": M_SAS_V1_METHOD,
            "key_agreement_protocol": key_agreement,
            "hash": hash_algo,
            "message_authentication_code": mac,
            "short_authentication_string": sas_methods,
            "commitment": commitment,
        }

        await self._send_to_device(
            M_KEY_VERIFICATION_ACCEPT, to_user, to_device, content
        )
        logger.info(
            f"[E2EE-Verify] 已发送 accept (commitment: {(commitment or '')[:16]}...)"
        )
