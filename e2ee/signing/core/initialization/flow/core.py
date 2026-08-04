"""Cross-signing initialization lifecycle flow."""

from astrbot.api import logger

from .....backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from ...compat import resolve_core_symbol


class CrossSigningCoreFlowCoreMixin:
    """Drive the cross-signing initialization state machine."""

    async def initialize(self):
        """初始化交叉签名"""
        if not resolve_core_symbol("CRYPTO_AVAILABLE", _DEFAULT_CRYPTO_AVAILABLE):
            logger.debug(
                "[E2EE-CrossSign] cryptography 不可用，无法生成/签名交叉签名密钥"
            )
            return

        try:
            self._load_local_keys()
            (
                server_master,
                server_self_signing,
                server_user_signing,
                keys_need_regen,
            ) = await self._query_server_cross_signing_state()

            if keys_need_regen:
                logger.debug(
                    "[E2EE-CrossSign] 检测到旧格式交叉签名 key ID，准备重新生成"
                )
                await self._generate_and_upload_keys(force_regen=True)
                return

            if server_master:
                return await self._initialize_from_server_state(
                    server_master,
                    server_self_signing,
                    server_user_signing,
                )

            try:
                await self._generate_and_upload_keys(
                    force_regen=not bool(self._master_priv),
                    reuse_master=bool(self._master_priv),
                )
            except Exception as e:
                logger.warning(f"[E2EE-CrossSign] 生成交叉签名密钥失败：{e}")
                logger.warning("[E2EE-CrossSign] 交叉签名功能将不可用")

        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 初始化失败：{e}")
