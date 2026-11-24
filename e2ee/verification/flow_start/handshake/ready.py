"""SAS ready event handling."""

from astrbot.api import logger

from .....constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)


class SASVerificationFlowReadyMixin:
    """处理 SAS ready 响应并启动后续验证。"""

    async def _handle_ready(self, sender: str, content: dict, transaction_id: str):
        """处理 ready 响应"""
        from_device = content.get("from_device")
        methods = content.get("methods", [])

        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            from_device,
        )
        if session is None:
            return

        if not session.get("we_started_it") or session.get("state") != "request_sent":
            await self._reject_unexpected_verification_event(
                session,
                transaction_id,
                "m.key.verification.ready",
                sender=sender,
                from_device=from_device,
            )
            return

        logger.info(
            "[E2EE-Verify] 对方已就绪："
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

        session["state"] = "ready"
        session["their_device"] = from_device

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
            if session.get("is_in_room") and session.get("room_id"):
                await self._send_in_room_start(session["room_id"], transaction_id)
            else:
                await self._send_start(sender, from_device, transaction_id)
        else:
            logger.warning(f"[E2EE-Verify] 无共同验证方法：{methods}")
            await self._cancel_bound_verification_session(
                session,
                transaction_id,
                "m.unknown_method",
                "No common verification methods",
                sender=sender,
                from_device=from_device,
            )
