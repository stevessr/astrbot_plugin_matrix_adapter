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

        key_agreement = self._pick_algorithm(KEY_AGREEMENT_PROTOCOLS, their_key_agreement)
        hash_algo = self._pick_algorithm(HASHES, their_hashes)
        mac = self._pick_algorithm(MESSAGE_AUTHENTICATION_CODES, their_macs)
        sas_methods = [s for s in SHORT_AUTHENTICATION_STRING if s in their_sas]

        session = self._sessions.get(transaction_id, {})
        if not key_agreement or not hash_algo or not mac or not sas_methods:
            logger.warning(
                "[E2EE-Verify] 房间内 SAS 协商失败：没有完整的共同算法集合"
            )
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "No common SAS verification algorithms",
            )
            return

        our_public_key = await self._resolve_room_accept_public_key(session)
        if not our_public_key:
            logger.warning("[E2EE-Verify] 无法初始化真实房间内 SAS 公钥，取消验证")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "Unable to initialize SAS verification",
            )
            return

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
        session["accept_sent"] = True
        session["state"] = "accept_sent"
        logger.info(
            f"[E2EE-Verify] 已发送房间内 accept (commitment: {(commitment or '')[:16]}...)"
        )
