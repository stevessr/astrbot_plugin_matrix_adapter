"""In-room SAS ready/accept/key handshake messages."""

import base64
import hashlib
import secrets
import sys

from astrbot.api import logger

from ....constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_READY,
)
from ..constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
    VODOZEMAC_SAS_AVAILABLE,
    Sas,
)
from ..crypto_utils import _canonical_json


def _vodozemac_sas_available() -> bool:
    package = sys.modules.get(__package__)
    if package is not None:
        return bool(
            getattr(package, "VODOZEMAC_SAS_AVAILABLE", VODOZEMAC_SAS_AVAILABLE)
        )
    return VODOZEMAC_SAS_AVAILABLE


class SASVerificationSendRoomHandshakeMixin:
    """发送房间内 ready、accept 和 key 握手消息。"""

    async def _send_in_room_ready(self, room_id: str, transaction_id: str):
        """发送房间内 ready 响应"""
        session = self._sessions.get(transaction_id, {})
        content = {
            "from_device": self.device_id,
            "methods": self._get_supported_verification_methods(session.get("sender")),
        }
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_READY, content, transaction_id
        )
        logger.info("[E2EE-Verify] 已发送 ready")

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

        sas = session.get("sas")
        if sas and _vodozemac_sas_available():
            our_public_key = sas.public_key.to_base64()
        elif _vodozemac_sas_available():
            logger.warning(
                "[E2EE-Verify] SAS object not in session, creating new SAS for accept"
            )
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
                session["sas"] = sas
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
        else:
            logger.warning(
                "[E2EE-Verify] vodozemac not available, using fallback random key"
            )
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        # 计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))
        # 根据 Matrix 规范和 matrix-rust-sdk 实现，m.relates_to 应该包含在 canonical JSON 中
        canonical_start = _canonical_json(start_content)
        commitment_data = our_public_key + canonical_start
        commitment = (
            base64.b64encode(hashlib.sha256(commitment_data.encode("utf-8")).digest())
            .decode()
            .rstrip("=")
        )

        logger.debug(
            f"[E2EE-Verify] Commitment: public_key={(our_public_key or '')[:16]}..., "
            f"has_m.relates_to={'m.relates_to' in start_content}"
        )

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


__all__ = ["SASVerificationSendRoomHandshakeMixin"]
