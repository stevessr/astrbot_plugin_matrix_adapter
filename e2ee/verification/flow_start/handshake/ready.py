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

        logger.info(
            "[E2EE-Verify] 对方已就绪："
            f"device={self._mask_identifier(from_device)} methods={methods}"
        )

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
