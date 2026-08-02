"""SAS start event handling."""

from astrbot.api import logger

from .....constants import M_RECIPROCATE_V1_METHOD


class SASVerificationFlowStartEventMixin:
    """处理 SAS start 事件并发送 accept。"""

    async def _handle_start(self, sender: str, content: dict, transaction_id: str):
        """处理验证开始"""
        from_device = content.get("from_device")
        method = content.get("method")
        their_commitment = content.get("commitment")

        masked_their_commitment = (
            their_commitment[:16] if isinstance(their_commitment, str) else "None"
        )
        logger.info(
            f"[E2EE-Verify] 验证开始：method={method} "
            f"commitment={masked_their_commitment}..."
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "started"
        session["method"] = method
        session["their_commitment"] = their_commitment
        session["start_content"] = content
        session["we_are_initiator"] = False  # 收到 start，说明对方是 Initiator

        if method == M_RECIPROCATE_V1_METHOD:
            handled = await self._handle_reciprocate_start(
                sender,
                from_device,
                content,
                transaction_id,
                session,
            )
            if handled:
                return

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        if self.auto_verify_mode in ("auto_accept", "manual"):
            if from_device:
                if is_in_room and room_id:
                    await self._send_in_room_accept(room_id, transaction_id, content)
                else:
                    await self._send_accept(
                        sender, from_device, transaction_id, content
                    )
