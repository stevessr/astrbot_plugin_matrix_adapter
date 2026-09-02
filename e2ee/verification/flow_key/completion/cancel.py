"""Verification cancellation state handling."""

from astrbot.api import logger


class SASVerificationFlowCancelMixin:
    """处理验证取消状态。"""

    async def _handle_cancel(self, sender: str, content: dict, transaction_id: str):
        """处理验证取消"""
        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            content.get("from_device"),
        )
        if session is None:
            return

        code = content.get("code")
        reason = content.get("reason")

        logger.warning(f"[E2EE-Verify] ❌ 验证被取消：code={code} reason={reason}")
        session["state"] = "cancelled"
        session["cancel_code"] = code
        session["cancel_reason"] = reason
