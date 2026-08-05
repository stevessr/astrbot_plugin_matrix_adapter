"""SAS key-exchange orchestration."""


class SASVerificationFlowKeyCoreOrchestratorMixin:
    """处理 commitment、公钥交换和 SAS 共享密钥计算。"""

    async def _handle_key(self, sender: str, content: dict, transaction_id: str):
        """处理密钥交换 - 使用真正的 X25519"""
        session = self._sessions.get(transaction_id, {})

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

        await self._compute_sas_shared_secret(
            session,
            sender=sender,
            their_device=their_device,
            their_key=their_key,
            transaction_id=transaction_id,
        )

        await self._send_sas_mac(
            session,
            sender,
            transaction_id,
            is_in_room=is_in_room,
            room_id=room_id,
            their_device=their_device,
        )


__all__ = ["SASVerificationFlowKeyCoreOrchestratorMixin"]
