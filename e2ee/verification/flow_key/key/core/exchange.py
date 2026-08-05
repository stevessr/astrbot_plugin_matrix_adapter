"""SAS key exchange bookkeeping and own-key sending."""


class SASVerificationFlowKeyExchangeMixin:
    """Record the peer key and send our own key when still pending."""

    async def _store_key_and_send_own(
        self,
        sender: str,
        session: dict,
        transaction_id: str,
        their_key: str,
    ) -> tuple[bool, str | None, str]:
        """Return ``(is_in_room, room_id, their_device)`` for later use."""
        session["their_key"] = their_key
        session["state"] = "key_exchanged"

        # Check if this is an in-room verification
        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        their_device = session.get("from_device", session.get("their_device", ""))

        # 如果我们还没发送自己的公钥，先发送
        if not session.get("key_sent"):
            if self.auto_verify_mode in ("auto_accept", "manual"):
                if is_in_room and room_id:
                    await self._send_in_room_key(room_id, transaction_id)
                else:
                    await self._send_key(sender, their_device, transaction_id)
                session["key_sent"] = True

        return is_in_room, room_id, their_device


__all__ = ["SASVerificationFlowKeyExchangeMixin"]
