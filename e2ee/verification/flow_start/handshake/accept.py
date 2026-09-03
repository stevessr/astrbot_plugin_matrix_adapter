"""SAS accept event handling."""

from astrbot.api import logger

from .....constants import M_SAS_V1_METHOD


class SASVerificationFlowAcceptMixin:
    """处理 SAS accept 事件并发送公钥。"""

    async def _handle_accept(self, sender: str, content: dict, transaction_id: str):
        """处理验证接受"""
        from_device = content.get("from_device")
        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            from_device,
        )
        if session is None:
            return

        start_content = session.get("start_content")
        if (
            not session.get("we_are_initiator")
            or not session.get("start_sent")
            or session.get("state") != "start_sent"
            or not isinstance(start_content, dict)
            or start_content.get("method") != M_SAS_V1_METHOD
        ):
            await self._reject_unexpected_verification_event(
                session,
                transaction_id,
                "m.key.verification.accept",
                sender=sender,
                from_device=from_device,
            )
            return

        method = content.get("method")
        commitment = content.get("commitment")
        key_agreement = content.get("key_agreement_protocol")
        hash_algo = content.get("hash")
        mac = content.get("message_authentication_code")
        sas_methods = content.get("short_authentication_string")

        if (
            method != M_SAS_V1_METHOD
            or not isinstance(commitment, str)
            or not commitment
            or not isinstance(key_agreement, str)
            or not key_agreement
            or not isinstance(hash_algo, str)
            or not hash_algo
            or not isinstance(mac, str)
            or not mac
            or not isinstance(sas_methods, list)
            or not sas_methods
            or not all(isinstance(value, str) and value for value in sas_methods)
        ):
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.invalid_message",
                "Malformed SAS accept event",
                sender=sender,
                from_device=from_device,
            )
            return

        offered_key_agreements = start_content.get("key_agreement_protocols") or []
        offered_hashes = start_content.get("hashes") or []
        offered_macs = start_content.get("message_authentication_codes") or []
        offered_sas = start_content.get("short_authentication_string") or []
        if (
            key_agreement not in offered_key_agreements
            or hash_algo not in offered_hashes
            or mac not in offered_macs
            or any(value not in offered_sas for value in sas_methods)
        ):
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "SAS accept selected an algorithm not offered by start",
                sender=sender,
                from_device=from_device,
            )
            return

        logger.info(
            "[E2EE-Verify] 对方接受验证："
            f"key_agreement={key_agreement} hash={hash_algo} mac={mac}"
        )

        session["state"] = "accepted"
        session["their_commitment"] = commitment
        session["key_agreement"] = key_agreement
        session["hash"] = hash_algo
        session["mac"] = mac
        session["sas_methods"] = list(sas_methods)

        if self.auto_verify_mode in ("auto_accept", "manual"):
            is_in_room = session.get("is_in_room", False)
            room_id = session.get("room_id")
            target_device = (
                from_device
                or session.get("their_device")
                or session.get("from_device", "")
            )

            if is_in_room and room_id:
                await self._send_in_room_key(room_id, transaction_id)
            else:
                await self._send_key(sender, target_device, transaction_id)
