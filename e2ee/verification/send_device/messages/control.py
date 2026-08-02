"""Verification done and cancel messages."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_CANCEL, M_KEY_VERIFICATION_DONE


class SASVerificationSendDeviceControlMixin:
    async def _send_done(self, to_user: str, to_device: str, transaction_id: str):
        """发送 done"""
        content = {"transaction_id": transaction_id}
        await self._send_to_device(M_KEY_VERIFICATION_DONE, to_user, to_device, content)
        logger.info("[E2EE-Verify] 已发送 done")

    async def _send_cancel(
        self, to_user: str, to_device: str, transaction_id: str, code: str, reason: str
    ):
        """发送取消"""
        content = {
            "transaction_id": transaction_id,
            "code": code,
            "reason": reason,
        }
        await self._send_to_device(
            M_KEY_VERIFICATION_CANCEL, to_user, to_device, content
        )
        logger.info(f"[E2EE-Verify] 已发送 cancel: {code} - {reason}")
