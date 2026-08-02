"""SAS verification handshake message construction."""

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
    M_KEY_VERIFICATION_START,
    M_SAS_V1_METHOD,
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


class SASVerificationSendDeviceHandshakeMixin:
    """发送 SAS ready、start、accept 和 key 握手消息。"""

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
        logger.info("[E2EE-Verify] 已发送 ready")

    async def _send_start(self, to_user: str, to_device: str, transaction_id: str):
        """发送 start 消息 (作为发起者)"""
        # 生成 commitment

        # 1. 生成公钥 (start 时不发送，但在 start 后发送 key 时会用到)
        # 此时我们需要创建一个 SAS 对象
        sas = None
        if _vodozemac_sas_available():
            try:
                sas = Sas()
                our_public_key = sas.public_key.to_base64()
            except Exception as e:
                logger.warning(f"Failed to create SAS: {e}")
                our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()
        else:
            our_public_key = base64.b64encode(secrets.token_bytes(32)).decode()

        session = self._sessions.get(transaction_id, {})
        session["sas"] = sas
        session["our_public_key"] = our_public_key

        # 2. 构造 start 内容
        content = {
            "from_device": self.device_id,
            "method": M_SAS_V1_METHOD,
            "key_agreement_protocols": KEY_AGREEMENT_PROTOCOLS,
            "hashes": HASHES,
            "message_authentication_codes": MESSAGE_AUTHENTICATION_CODES,
            "short_authentication_string": SHORT_AUTHENTICATION_STRING,
            "transaction_id": transaction_id,
        }
        # The accept-side commitment hashes this exact content object. Keep a
        # byte-for-byte semantic copy for validation when the peer key arrives.
        session["start_content"] = dict(content)
        session["we_are_initiator"] = True

        # 3. 计算 commitment (注意：start 消息本身不包含 commitment，
        # 而是 accept 消息包含。但是等等，根据 Matrix 流程：
        # Initiator sends start.
        # Responder sends accept (with commitment).
        # Initiator sends key.
        # Responder sends key.
        # 所以 start 消息只需要包含支持的算法)

        # 实际上 start 消息不需要 commitment。
        # Commitment 是 Responder 发送的。

        await self._send_to_device(
            M_KEY_VERIFICATION_START, to_user, to_device, content
        )
        logger.info("[E2EE-Verify] 已发送 start")

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

    async def _send_key(self, to_user: str, to_device: str, transaction_id: str):
        """发送公钥"""
        session = self._sessions.get(transaction_id, {})

        sas = session.get("sas")
        if sas and _vodozemac_sas_available():
            # vodozemac 返回 Key 对象，需要转换为 base64 字符串
            our_public_key = sas.public_key.to_base64()
        else:
            our_public_key = session.get(
                "our_public_key", base64.b64encode(secrets.token_bytes(32)).decode()
            )

        session["our_public_key"] = our_public_key
        session["key_sent"] = True

        content = {
            "transaction_id": transaction_id,
            "key": our_public_key,
        }

        await self._send_to_device(M_KEY_VERIFICATION_KEY, to_user, to_device, content)
        logger.info(f"[E2EE-Verify] 已发送 key: {(our_public_key or '')[:20]}...")


__all__ = ["SASVerificationSendDeviceHandshakeMixin"]
