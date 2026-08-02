"""SAS public-key message construction."""

import base64
import secrets

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_KEY
from .compat import _vodozemac_sas_available


class SASVerificationHandshakeKeyMixin:
    """构造 SAS 公钥消息。"""

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
