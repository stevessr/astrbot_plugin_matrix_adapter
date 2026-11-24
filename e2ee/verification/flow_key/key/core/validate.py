"""Incoming SAS key validation and commitment checks."""

from astrbot.api import logger


class SASVerificationFlowKeyValidateMixin:
    """Validate the peer key and its commitment."""

    async def _validate_key_and_commitment(
        self,
        sender: str,
        content: dict,
        transaction_id: str,
        session: dict,
    ) -> str | None:
        """Return the validated peer key, or ``None`` to abort."""
        their_key = content.get("key")
        their_device = session.get("from_device") or session.get("their_device")

        if not isinstance(their_key, str) or not their_key:
            logger.warning("[E2EE-Verify] 对方公钥缺失或格式不正确")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.invalid_message",
                "Missing or malformed verification key",
                sender=sender,
                from_device=their_device,
            )
            return None
        logger.info("[E2EE-Verify] 收到对方公钥")

        # commitment = SHA256(public_key || canonical_json(start_content))
        their_commitment = session.get("their_commitment")
        start_content = session.get("start_content")
        if session.get("we_are_initiator"):
            if not isinstance(their_commitment, str) or not their_commitment:
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.invalid_message",
                    "Missing SAS commitment",
                    sender=sender,
                    from_device=their_device,
                )
                return None
            if not isinstance(start_content, dict) or not self._verify_commitment(
                their_key,
                start_content,
                their_commitment,
            ):
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.mismatched_commitment",
                    "Commitment verification failed",
                    sender=sender,
                    from_device=their_device,
                )
                return None
            logger.info("[E2EE-Verify] ✅ Commitment 验证通过")

        return their_key


__all__ = ["SASVerificationFlowKeyValidateMixin"]
