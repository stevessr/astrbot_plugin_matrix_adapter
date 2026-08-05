"""Preparing self-verification QR codes for same-account peers."""

import secrets

from astrbot.api import logger


class SASVerificationFlowQRPrepareOrchestratorMixin:
    """Prepare and store a self-verification QR for a peer device."""

    async def _maybe_prepare_self_verification_qr(
        self,
        sender: str,
        peer_device: str | None,
        methods: object,
        transaction_id: str,
    ) -> bool:
        if not self._check_self_verification_qr_ready(sender, peer_device, methods):
            return False

        session = self._sessions.setdefault(transaction_id, {})
        if session.get("qr_payload"):
            return True

        try:
            (
                peer_device_key,
                current_device_key,
                master_key,
                response,
            ) = await self._fetch_self_verification_qr_keys(
                sender,
                peer_device,
                session,
            )
            if not current_device_key or not peer_device_key or not master_key:
                logger.warning(
                    "[E2EE-Verify] QR 自验证准备失败：缺少必要密钥 "
                    f"(current={bool(current_device_key)} peer={bool(peer_device_key)} master={bool(master_key)})"
                )
                return False

            mode, key1, key2 = self._select_self_verification_qr_mode(
                response,
                sender,
                peer_device_key,
                current_device_key,
                master_key,
            )

            shared_secret = secrets.token_bytes(16)
            await self._build_self_verification_qr_session(
                transaction_id,
                session,
                mode,
                key1,
                key2,
                shared_secret,
                peer_device,
            )
            return True
        except Exception as e:
            logger.warning(f"[E2EE-Verify] 准备同账号 QR 自验证失败：{e}")
            return False


__all__ = ["SASVerificationFlowQRPrepareOrchestratorMixin"]
