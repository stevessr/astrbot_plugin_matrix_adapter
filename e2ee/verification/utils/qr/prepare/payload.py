"""Self-verification QR payload construction and display."""

from astrbot.api import logger

from ....crypto_utils import _encode_unpadded_base64


class SASVerificationFlowQRPreparePayloadMixin:
    """Build the QR payload, display it, and notify the admin."""

    async def _build_self_verification_qr_session(
        self,
        transaction_id: str,
        session: dict,
        mode: int,
        key1: str,
        key2: str,
        shared_secret: bytes,
        peer_device: str,
    ) -> None:
        payload = self._build_self_verification_qr_payload(
            transaction_id,
            key1,
            key2,
            shared_secret,
            mode,
        )
        session["qr_mode"] = mode
        session["qr_payload"] = payload
        session["qr_shared_secret"] = shared_secret
        session["qr_shared_secret_b64"] = _encode_unpadded_base64(shared_secret)

        build_terminal_qr = getattr(self, "_build_terminal_qr", None)
        if callable(build_terminal_qr):
            session["qr_ascii"] = build_terminal_qr(payload)

        logger.info(
            "[E2EE-Verify] 已生成同账号 QR 自验证码："
            f"device={self._mask_identifier(peer_device)} "
            f"mode=0x{mode:02x} txn={self._mask_txn_id(transaction_id)}"
        )
        qr_ascii = str(session.get("qr_ascii") or "").rstrip()
        if qr_ascii:
            logger.info(
                f"[E2EE-Verify] 请在另一台设备上扫描以下二维码完成验证：\n{qr_ascii}"
            )

        notify_qr = getattr(self, "_notify_admin_for_qr_code", None)
        if callable(notify_qr):
            await notify_qr(session, transaction_id)


__all__ = ["SASVerificationFlowQRPreparePayloadMixin"]
