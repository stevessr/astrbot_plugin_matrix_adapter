"""SAS accept negotiation and commitment construction."""

import base64
import hashlib
import secrets

from astrbot.api import logger

from .....constants import (
    KEY_AGREEMENT_PROTOCOLS,
    M_KEY_VERIFICATION_ACCEPT,
    M_SAS_V1_METHOD,
)
from ...constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SHORT_AUTHENTICATION_STRING,
    Sas,
)
from ...crypto_utils import _canonical_json
from .compat import _vodozemac_sas_available


class SASVerificationHandshakeNegotiationMixin:
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

        # 生成我们的公钥
        sas = session.get("sas")
        if sas and _vodozemac_sas_available():
            # vodozemac 返回 Key 对象，需要转换为 base64 字符串
            our_public_key = sas.public_key.to_base64()
            logger.info(
                f"[E2EE-Verify] Using existing SAS object, public_key: {our_public_key}"
            )
        elif _vodozemac_sas_available():
            # SAS object not in session, create new one
            logger.warning(
                "[E2EE-Verify] SAS object not in session, creating new SAS for accept"
            )
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
                session["sas"] = sas
                logger.info(
                    f"[E2EE-Verify] Created new SAS, public_key: {our_public_key}"
                )
            except Exception as e:
                logger.error(f"[E2EE-Verify] Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
                logger.warning(
                    "[E2EE-Verify] Using fallback random key (commitment will fail!)"
                )
        else:
            logger.warning(
                "[E2EE-Verify] vodozemac not available, using fallback random key"
            )
            # 回退：生成随机密钥 (仅用于显示)
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session["our_public_key"] = our_public_key
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        # 计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))
        # 根据 Matrix 规范，public_key 使用 unpadded base64 编码
        commitment_data = our_public_key + _canonical_json(start_content)
        commitment = (
            base64.b64encode(hashlib.sha256(commitment_data.encode()).digest())
            .decode()
            .rstrip("=")
        )

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
