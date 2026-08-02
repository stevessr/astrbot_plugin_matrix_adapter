"""Verification cancellation state handling."""

from astrbot.api import logger


class SASVerificationFlowCancelMixin:
    """处理验证取消状态。"""

    async def _handle_cancel(self, sender: str, content: dict, transaction_id: str):
        """处理验证取消"""
        code = content.get("code")
        reason = content.get("reason")

        logger.warning(f"[E2EE-Verify] ❌ 验证被取消：code={code} reason={reason}")

        if transaction_id in self._sessions:
            self._sessions[transaction_id]["state"] = "cancelled"
            self._sessions[transaction_id]["cancel_code"] = code
            self._sessions[transaction_id]["cancel_reason"] = reason
