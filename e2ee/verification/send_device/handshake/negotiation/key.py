"""Accept-side public key resolution and commitment computation."""

import base64
import hashlib
import secrets

from astrbot.api import logger

from ....constants import Sas
from ....crypto_utils import _canonical_json
from ..compat import _vodozemac_sas_available


class SASVerificationHandshakeNegotiationKeyMixin:
    """协商 SAS 算法并构造 accept 消息。"""

    async def _resolve_our_public_key(self, session: dict) -> str:
        """生成或复用 accept 用的 SAS 公钥。"""
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
        return our_public_key

    @staticmethod
    def _compute_accept_commitment(our_public_key: str, start_content: dict) -> str:
        """计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))"""
        # 根据 Matrix 规范，public_key 使用 unpadded base64 编码
        commitment_data = our_public_key + _canonical_json(start_content)
        return (
            base64.b64encode(hashlib.sha256(commitment_data.encode()).digest())
            .decode()
            .rstrip("=")
        )
