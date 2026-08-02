"""SAS ready and start message construction."""

import base64
import secrets

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
