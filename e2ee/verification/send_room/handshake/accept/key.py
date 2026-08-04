"""Accept-side public key resolution and commitment computation."""

import base64
import hashlib
import secrets

from astrbot.api import logger

from ....constants import Sas
from ....crypto_utils import _canonical_json
from ..compat import _vodozemac_sas_available


class SASVerificationSendRoomAcceptKeyMixin:
    """解析房间内 accept 公钥并计算 commitment。"""

    async def _resolve_room_accept_public_key(self, session: dict) -> str:
        """生成或复用 accept 用的 SAS 公钥。"""
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
        return our_public_key

    @staticmethod
    def _compute_room_accept_commitment(
        our_public_key: str, start_content: dict
    ) -> str:
        """计算 commitment = UnpaddedBase64(SHA256(public_key || canonical_json(start_content)))"""
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
        return commitment
