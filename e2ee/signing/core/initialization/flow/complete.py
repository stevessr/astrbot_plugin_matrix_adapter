"""Completing missing cross-signing keys after initialization."""

from astrbot.api import logger


class CrossSigningCoreFlowCompleteMixin:
    """Drive the cross-signing initialization state machine."""

    async def _ensure_server_state_complete(
        self, server_self_signing, server_user_signing
    ):
        """Complete any missing cross-signing keys or log readiness."""
        if server_self_signing and server_user_signing:
            logger.debug("[E2EE-CrossSign] 交叉签名密钥已就绪")
            return

        if self._master_priv:
            try:
                # 补全缺失的交叉签名密钥（如用户签名密钥），尽可能复用主密钥
                await self._generate_and_upload_keys(
                    force_regen=False,
                    reuse_master=True,
                )
            except Exception as e:
                logger.warning(f"[E2EE-CrossSign] 补全交叉签名密钥失败：{e}")
                logger.warning("[E2EE-CrossSign] 部分交叉签名功能可能不可用")
