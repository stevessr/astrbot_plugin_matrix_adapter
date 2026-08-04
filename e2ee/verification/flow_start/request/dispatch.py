"""Verification mode dispatch for incoming requests."""

from astrbot.api import logger

from .....constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)


class SASVerificationFlowRequestDispatchMixin:
    """按 auto_verify_mode 分派验证请求。"""

    async def _dispatch_verification_mode(
        self,
        session: dict,
        sender: str,
        from_device: str,
        methods: list,
        transaction_id: str,
    ):
        if self.auto_verify_mode == "auto_reject":
            logger.info("[E2EE-Verify] 自动拒绝验证请求 (mode=auto_reject)")
            await self._send_cancel(
                sender, from_device, transaction_id, "m.user", "自动拒绝"
            )
            return

        if self.auto_verify_mode == "manual":
            logger.info(
                "[E2EE-Verify] 手动模式，发送 ready 并等待管理员确认 (mode=manual)"
            )
            await self._accept_verification_request(
                sender,
                from_device,
                methods,
                transaction_id,
            )
            return

        # auto_accept: 发送 ready
        if self._supports_method(
            methods, M_SAS_V1_METHOD
        ) or self._can_continue_with_qr(sender, methods):
            logger.info("[E2EE-Verify] 自动接受验证请求 (mode=auto_accept)")
            await self._accept_verification_request(
                sender,
                from_device,
                methods,
                transaction_id,
            )
        else:
            logger.warning(f"[E2EE-Verify] 不支持的验证方法：{methods}")
            await self._send_cancel(
                sender,
                from_device,
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )

    async def _accept_verification_request(
        self,
        sender: str,
        from_device: str,
        methods: list,
        transaction_id: str,
    ):
        if self._supports_method(
            methods, M_SAS_V1_METHOD
        ) or self._can_continue_with_qr(sender, methods):
            await self._send_ready(sender, from_device, transaction_id)
            await self._maybe_prepare_self_verification_qr(
                sender, from_device, methods, transaction_id
            )
            if (
                sender == self.user_id
                and self._supports_method(methods, M_QR_CODE_SHOW_V1_METHOD)
                and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
            ):
                notify_scan = getattr(self, "_notify_admin_to_scan_peer_qr", None)
                if callable(notify_scan):
                    await notify_scan(self._sessions[transaction_id], transaction_id)
        else:
            await self._send_cancel(
                sender,
                from_device,
                transaction_id,
                "m.unknown_method",
                "不支持的验证方法",
            )
