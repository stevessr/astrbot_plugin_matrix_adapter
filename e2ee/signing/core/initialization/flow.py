"""Cross-signing initialization lifecycle flow."""

from astrbot.api import logger

from ....backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from ....constants import DEVICE_SECRET_REQUEST_PENDING, FORCE_OVERWRITE_SERVER_KEYS
from ..compat import resolve_core_symbol


class CrossSigningCoreFlowMixin:
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

    async def _initialize_from_server_state(
        self,
        server_master,
        server_self_signing,
        server_user_signing,
    ):
        """Recover or restore cross-signing state from the server."""
        local_ready = self._has_private_keys_for_server_state(
            server_self_signing,
            server_user_signing,
        )
        local_matches = local_ready and self._local_keys_match_server(
            server_master,
            server_self_signing,
            server_user_signing,
        )

        if not local_matches:
            await self._restore_private_keys_from_secret_storage(
                server_master,
                server_self_signing,
                server_user_signing,
            )
            local_ready = self._has_private_keys_for_server_state(
                server_self_signing,
                server_user_signing,
            )
            local_matches = local_ready and self._local_keys_match_server(
                server_master,
                server_self_signing,
                server_user_signing,
            )

            if not local_matches:
                request_status = await self._request_missing_private_keys_from_devices(
                    server_master,
                    server_self_signing,
                    server_user_signing,
                )
                if request_status == resolve_core_symbol(
                    "DEVICE_SECRET_REQUEST_PENDING",
                    DEVICE_SECRET_REQUEST_PENDING,
                ):
                    logger.info(
                        "[E2EE-CrossSign] 已向其他设备请求 cross-signing 私钥，"
                        "等待设备间恢复后再继续"
                    )
                    return

                overwrite_reason = (
                    "服务器已有交叉签名密钥，但本地缺少对应私钥"
                    if not local_ready
                    else "本地私钥与服务器公钥不匹配（可能已被其他客户端重置）"
                )
                if resolve_core_symbol(
                    "FORCE_OVERWRITE_SERVER_KEYS",
                    FORCE_OVERWRITE_SERVER_KEYS,
                ):
                    logger.warning(
                        f"[E2EE-CrossSign] {overwrite_reason}，恢复路径失败后将重新生成"
                    )
                    await self._generate_and_upload_keys(force_regen=True)
                    return

                logger.warning(
                    f"[E2EE-CrossSign] {overwrite_reason}."
                    "如需强行覆盖服务器密钥，请将 FORCE_OVERWRITE_SERVER_KEYS 设置为 True"
                )
                return

        await self._ensure_server_state_complete(
            server_self_signing,
            server_user_signing,
        )

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
