"""QR reciprocate verification handling."""

import hmac

from astrbot.api import logger


class SASVerificationFlowReciprocateMixin:
    """校验 QR shared secret 并完成 reciprocate 流程。"""

    async def _handle_reciprocate_start(
        self,
        sender: str,
        from_device: str | None,
        content: dict,
        transaction_id: str,
        session: dict,
    ) -> bool:
        expected_secret = session.get("qr_shared_secret_b64")
        received_secret = content.get("secret")
        if not isinstance(expected_secret, str) or not expected_secret:
            logger.warning("[E2EE-Verify] 收到 reciprocate，但当前会话没有待确认的 QR")
            if from_device:
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.unexpected_message",
                    "No QR code is pending for this verification",
                    sender=sender,
                    from_device=from_device,
                )
            return True
        if not isinstance(received_secret, str) or not received_secret:
            logger.warning("[E2EE-Verify] 收到 reciprocate，但缺少 secret")
            if from_device:
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.invalid_message",
                    "Missing reciprocate secret",
                    sender=sender,
                    from_device=from_device,
                )
            return True
        if not hmac.compare_digest(received_secret, expected_secret):
            logger.warning("[E2EE-Verify] QR reciprocate secret 不匹配")
            if from_device:
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.key_mismatch",
                    "QR shared secret mismatch",
                    sender=sender,
                    from_device=from_device,
                )
            return True

        session["qr_reciprocated"] = True
        session["qr_confirmed"] = self.auto_verify_mode == "auto_accept"
        session["state"] = "qr_scanned"
        logger.info(
            "[E2EE-Verify] 对端已扫描 QR："
            f"device={self._mask_identifier(from_device)} "
            f"txn={self._mask_txn_id(transaction_id)}"
        )

        if self.auto_verify_mode == "auto_reject":
            if from_device:
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.user",
                    "自动拒绝",
                    sender=sender,
                    from_device=from_device,
                )
            return True

        if self.auto_verify_mode == "manual":
            notify = getattr(self, "_notify_admin_for_qr_reciprocation", None)
            if callable(notify):
                await notify(session, transaction_id)
            return True

        if not from_device:
            return True

        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")
        if not session.get("done_sent"):
            if is_in_room and room_id:
                await self._send_in_room_done(room_id, transaction_id)
            else:
                await self._send_done(sender, from_device, transaction_id)
            session["done_sent"] = True
        return True


__all__ = ["SASVerificationFlowReciprocateMixin"]
