"""Successful MAC verification completion."""

from astrbot.api import logger


class SASVerificationFlowMACFinishMixin:
    """Mark the session verified and notify the peer."""

    async def _complete_mac_verification(
        self,
        session,
        sender,
        their_device,
        transaction_id,
        is_in_room,
        room_id,
    ):
        session["mac_verified"] = True
        logger.info(
            "[E2EE-Verify] ✅ MAC 校验通过："
            f"device={self._mask_identifier(their_device)}"
        )

        await self._send_mac_done(
            session,
            sender,
            transaction_id,
            is_in_room,
            room_id,
        )


__all__ = ["SASVerificationFlowMACFinishMixin"]
