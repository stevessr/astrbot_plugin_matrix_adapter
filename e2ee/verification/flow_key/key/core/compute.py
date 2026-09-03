"""SAS shared-secret computation and manual verification notice."""

from astrbot.api import logger

from ..compat import _vodozemac_sas_available


class SASVerificationFlowKeyComputeMixin:
    """Compute the real Matrix SAS shared secret via vodozemac."""

    async def _compute_sas_shared_secret(
        self,
        session: dict,
        *,
        sender: str,
        their_device: str,
        their_key: str,
        transaction_id: str,
    ) -> bool:
        """Return True only after a real Curve25519 SAS exchange is established."""
        if session.get("established_sas") and (
            session.get("sas_emojis") or session.get("sas_decimals")
        ):
            logger.debug("[E2EE-Verify] SAS 已计算，跳过重复计算")
            return True

        sas = session.get("sas")
        if not sas or not _vodozemac_sas_available() or not their_key:
            logger.error(
                "[E2EE-Verify] 无法建立真实 SAS：缺少 vodozemac/SAS/peer key"
            )
            return False

        if not await self._compute_vodozemac_sas(
            session,
            sas=sas,
            sender=sender,
            their_device=their_device,
            their_key=their_key,
            transaction_id=transaction_id,
        ):
            return False

        if self.auto_verify_mode == "manual" and not session.get("manual_notified"):
            session["manual_notified"] = True
            await self._notify_admin_for_verification(session, transaction_id)
        return True


__all__ = ["SASVerificationFlowKeyComputeMixin"]
