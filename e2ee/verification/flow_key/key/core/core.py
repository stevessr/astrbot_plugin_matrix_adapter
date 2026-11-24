"""SAS key-exchange orchestration."""

from .....constants import M_SAS_V1_METHOD


class SASVerificationFlowKeyCoreOrchestratorMixin:
    """处理 commitment、公钥交换和 SAS 共享密钥计算。"""

    async def _handle_key(self, sender: str, content: dict, transaction_id: str):
        """处理密钥交换 - 使用真正的 X25519"""
        from_device = content.get("from_device")
        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            from_device,
        )
        if session is None:
            return

        if session.get("method") != M_SAS_V1_METHOD or session.get("their_key"):
            await self._reject_unexpected_verification_event(
                session,
                transaction_id,
                "m.key.verification.key",
                sender=sender,
                from_device=from_device,
            )
            return

        if session.get("we_are_initiator"):
            ordered = (
                session.get("state") == "accepted"
                and session.get("start_sent")
                and session.get("key_sent")
                and bool(session.get("their_commitment"))
            )
        else:
            ordered = (
                session.get("state") == "accept_sent"
                and session.get("accept_sent")
            )

        if not ordered:
            await self._reject_unexpected_verification_event(
                session,
                transaction_id,
                "m.key.verification.key",
                sender=sender,
                from_device=from_device,
            )
            return

        their_key = await self._validate_key_and_commitment(
            sender,
            content,
            transaction_id,
            session,
        )
        if their_key is None:
            return

        is_in_room, room_id, their_device = await self._store_key_and_send_own(
            sender,
            session,
            transaction_id,
            their_key,
        )

        established = await self._compute_sas_shared_secret(
            session,
            sender=sender,
            their_device=their_device,
            their_key=their_key,
            transaction_id=transaction_id,
        )
        if not established:
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.key_mismatch",
                "Unable to establish SAS shared secret",
                sender=sender,
                from_device=from_device,
            )
            return

        await self._send_sas_mac(
            session,
            sender,
            transaction_id,
            is_in_room=is_in_room,
            room_id=room_id,
            their_device=their_device,
        )


__all__ = ["SASVerificationFlowKeyCoreOrchestratorMixin"]
