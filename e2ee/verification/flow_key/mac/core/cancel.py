"""MAC verification failure handling."""

from astrbot.api import logger


class SASVerificationFlowMACCancelMixin:
    """Cancel a SAS verification flow with a key-mismatch code."""

    async def _cancel_mac_verification(
        self,
        session: dict,
        sender: str,
        their_device: str,
        is_in_room: bool,
        room_id,
        transaction_id: str,
        reason: str,
    ):
        logger.warning(f"[E2EE-Verify] MAC 校验失败：{reason}")
        session["state"] = "cancelled"
        session["cancel_code"] = "m.key_mismatch"
        session["cancel_reason"] = reason
        if is_in_room and room_id:
            await self._send_in_room_cancel(
                room_id,
                transaction_id,
                "m.key_mismatch",
                reason,
            )
        else:
            await self._send_cancel(
                sender,
                their_device,
                transaction_id,
                "m.key_mismatch",
                reason,
            )

    async def _abort_mac_verification(
        self,
        session: dict,
        sender: str,
        their_device: str,
        is_in_room: bool,
        room_id,
        transaction_id: str,
    ):
        await self._cancel_mac_verification(
            session,
            sender,
            their_device,
            is_in_room,
            room_id,
            transaction_id,
            "MAC verification failed",
        )
