"""SAS verification ready/start/accept event handling."""

from astrbot.api import logger

from ....constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)


class SASVerificationFlowHandshakeMixin:
    """处理 ready、start 和 accept 事件。"""

    async def _handle_ready(self, sender: str, content: dict, transaction_id: str):
        """处理 ready 响应"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])

        logger.info(
            "[E2EE-Verify] 对方已就绪："
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

        session = self._sessions.get(transaction_id, {})
        session["state"] = "ready"
        session["their_device"] = from_device

        # 如果是我们发起的验证（即我们在等待 ready），我们需要发送 start
        if session.get("we_started_it"):
            qr_prepared = await self._maybe_prepare_self_verification_qr(
                sender, from_device, methods, transaction_id
            )
            if qr_prepared:
                logger.info("[E2EE-Verify] 作为发起者，优先展示 QR 自验证码")
                return

            if (
                sender == self.user_id
                and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
            ):
                session["state"] = "ready_for_qr_scan"
                logger.info(
                    "[E2EE-Verify] 对端支持展示 QR，等待扫码命令而不自动回退到 SAS"
                )
                notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                if callable(notify_scan):
                    await notify_scan(session, transaction_id)
                return

            logger.info("[E2EE-Verify] 作为发起者，开始 SAS 验证流程")
            if self._supports_method(methods, M_SAS_V1_METHOD):
                await self._send_start(sender, from_device, transaction_id)
            else:
                logger.warning(f"[E2EE-Verify] 无共同验证方法：{methods}")
                await self._send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unknown_method",
                    "No common methods",
                )

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


__all__ = ["SASVerificationFlowHandshakeMixin"]
