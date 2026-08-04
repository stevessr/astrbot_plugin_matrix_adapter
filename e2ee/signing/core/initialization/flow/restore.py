"""Recovering cross-signing state from the server or other devices."""

from astrbot.api import logger

from .....constants import DEVICE_SECRET_REQUEST_PENDING, FORCE_OVERWRITE_SERVER_KEYS
from ...compat import resolve_core_symbol


class CrossSigningCoreFlowRestoreMixin:
    """Drive the cross-signing initialization state machine."""

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
