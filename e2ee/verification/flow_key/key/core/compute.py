"""SAS shared-secret computation and manual verification notice."""

from astrbot.api import logger

from ..compat import _vodozemac_sas_available


class SASVerificationFlowKeyComputeMixin:
    """Compute the SAS shared secret, falling back when needed."""

    async def _compute_sas_shared_secret(
        self,
        session: dict,
        *,
        sender: str,
        their_device: str,
        their_key: str,
        transaction_id: str,
    ) -> None:
        sas = session.get("sas")

        # Safety check: Skip if SAS already computed (defensive measure)
        if session.get("established_sas") or session.get("sas_emojis"):
            logger.debug("[E2EE-Verify] SAS 已计算，跳过重复计算")
            return

        if sas and _vodozemac_sas_available() and their_key:
            if not await self._compute_vodozemac_sas(
                session,
                sas=sas,
                sender=sender,
                their_device=their_device,
                their_key=their_key,
                transaction_id=transaction_id,
            ):
                # 回退到简化实现
                self._compute_sas_fallback(session, their_key)
        else:
            # 使用简化实现
            self._compute_sas_fallback(session, their_key)

        if self.auto_verify_mode == "manual" and not session.get("manual_notified"):
            session["manual_notified"] = True
            await self._notify_admin_for_verification(session, transaction_id)


__all__ = ["SASVerificationFlowKeyComputeMixin"]
