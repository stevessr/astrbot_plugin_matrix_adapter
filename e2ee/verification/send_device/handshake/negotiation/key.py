"""Accept-side public key resolution and commitment computation."""

import base64
import hashlib

from astrbot.api import logger

from ....constants import Sas
from ....crypto_utils import _canonical_json
from ..compat import _vodozemac_sas_available


class SASVerificationHandshakeNegotiationKeyMixin:
    """协商 SAS 算法并构造 accept 消息。"""

    async def _resolve_our_public_key(self, session: dict) -> str | None:
        """生成或复用 accept 用的真实 SAS 公钥；不可用时返回 None。"""
        if not _vodozemac_sas_available() or Sas is None:
            logger.warning("[E2EE-Verify] vodozemac unavailable for SAS accept")
            return None

        sas = session.get("sas")
        if sas:
            try:
                our_public_key = sas.public_key.to_base64()
                logger.info(
                    f"[E2EE-Verify] Using existing SAS object, public_key: {our_public_key}"
                )
                return our_public_key
            except Exception as exc:
                logger.error(f"[E2EE-Verify] Existing SAS object is unusable: {exc}")
                return None

        logger.debug("[E2EE-Verify] SAS object not in session, creating one for accept")
        try:
            sas = Sas()
            our_public_key = sas.public_key.to_base64()
            session["sas"] = sas
            return our_public_key
        except Exception as e:
            logger.error(f"[E2EE-Verify] Failed to create SAS: {e}")
            return None

    @staticmethod
    def _compute_accept_commitment(our_public_key: str, start_content: dict) -> str:
        """计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))"""
        commitment_data = our_public_key + _canonical_json(start_content)
        return (
            base64.b64encode(hashlib.sha256(commitment_data.encode()).digest())
            .decode()
            .rstrip("=")
        )
