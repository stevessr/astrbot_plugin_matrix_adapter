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

        if not isinstance(their_key, str) or not their_key:
            logger.warning("[E2EE-Verify] 对方公钥缺失或格式不正确")
            return None
        logger.info("[E2EE-Verify] 收到对方公钥")

        # 根据 Matrix 规范验证 commitment
        # commitment = SHA256(公钥 || canonical_json(start_content))
        # 参考：https://spec.matrix.org/latest/client-server-api/#sas-verification
        their_commitment = session.get("their_commitment")
        start_content = session.get("start_content")
        if their_commitment and start_content and session.get("we_are_initiator"):
            if not self._verify_commitment(
                their_key,
                start_content,
                their_commitment,
            ):
                # 根据规范，commitment 不匹配应该取消验证
                if session.get("is_in_room") and session.get("room_id"):
                    await self._send_in_room_cancel(
                        session["room_id"],
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                else:
                    their_device = session.get(
                        "from_device", session.get("their_device", "")
                    )
                    await self._send_cancel(
                        sender,
                        their_device,
                        transaction_id,
                        "m.mismatched_commitment",
                        "Commitment verification failed",
                    )
                return None
            logger.info("[E2EE-Verify] ✅ Commitment 验证通过")

        return their_key


__all__ = ["SASVerificationFlowKeyValidateMixin"]
