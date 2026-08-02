"""SAS accept event handling."""

from astrbot.api import logger


class SASVerificationFlowAcceptMixin:
    """处理 SAS accept 事件并发送公钥。"""

    async def _handle_accept(self, sender: str, content: dict, transaction_id: str):
        """处理验证接受"""
        commitment = content.get("commitment")
        key_agreement = content.get("key_agreement_protocol")
        hash_algo = content.get("hash")
        mac = content.get("message_authentication_code")
        sas_methods = content.get("short_authentication_string") or []

        logger.info(
            "[E2EE-Verify] 对方接受验证："
            f"key_agreement={key_agreement} hash={hash_algo} mac={mac}"
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "accepted"
        session["their_commitment"] = commitment
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = sas_methods

        if self.auto_verify_mode in ("auto_accept", "manual"):
            # Check if this is an in-room verification
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")
            target_device = (
                content.get("from_device")
                or session.get("their_device")
                or session.get("from_device", "")
            )

            if is_in_room and room_id:
                await self._send_in_room_key(room_id, transaction_id)
            else:
                await self._send_key(sender, target_device, transaction_id)
