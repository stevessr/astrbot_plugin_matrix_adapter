import hashlib

from astrbot.api import logger

from ....constants import SAS_BYTES_LENGTH_6


class SASVerificationFlowSASMixin:
    def _compute_sas_fallback(self, session: dict, their_key: str):
        """回退的 SAS 计算（当 vodozemac SAS 不可用时）"""
        our_key = session.get("our_public_key", "")
        combined = f"{our_key}{their_key}".encode()
        sas_bytes = hashlib.sha256(combined).digest()[:SAS_BYTES_LENGTH_6]

        emojis = self._bytes_to_emoji(sas_bytes)
        decimals = self._bytes_to_decimal(sas_bytes)

        session["sas_bytes"] = sas_bytes
        session["sas_emojis"] = emojis
        session["sas_decimals"] = decimals

        emoji_str = " ".join(e[0] for e in emojis)
        logger.info(
            f"[E2EE-Verify] SAS 验证码 (fallback): {emoji_str} | 数字：{decimals}"
        )
