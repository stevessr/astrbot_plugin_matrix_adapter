"""Cross-signing construction and initialization lifecycle."""

from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger

from ....config.plugin import get_plugin_config as _DEFAULT_GET_PLUGIN_CONFIG
from ...backup.crypto_utils import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from ...constants import DEVICE_SECRET_REQUEST_PENDING, FORCE_OVERWRITE_SERVER_KEYS
from ...storage import build_e2ee_data_store as _DEFAULT_BUILD_E2EE_DATA_STORE
from .compat import resolve_core_symbol


class CrossSigningCoreInitializationMixin:
    """初始化交叉签名并准备本地持久化状态。"""

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        password: str | None = None,
        *,
        secret_storage=None,
        request_secret_from_devices: Callable[[str], Awaitable[str | None]]
        | None = None,
        repair_current_device_keys: Callable[[], Awaitable[None]] | None = None,
        namespace_key: str | None = None,
    ):
        self.client = client
        self.user_id = (
            user_id
            if isinstance(user_id, str) and user_id.startswith("@")
            else f"@{user_id}"
        )
        self.device_id = device_id
        self.olm = olm_machine
        self.password = password
        self.secret_storage = secret_storage
        self.request_secret_from_devices = request_secret_from_devices
        self.repair_current_device_keys = repair_current_device_keys

        self._master_key: str | None = None
        self._self_signing_key: str | None = None
        self._user_signing_key: str | None = None

        # 私钥（Raw 32B），仅本地持久化
        self._master_priv = None
        self._self_signing_priv = None
        self._user_signing_priv = None
        self._pending_secret_requests: set[str] = set()

        get_config = resolve_core_symbol(
            "get_plugin_config", _DEFAULT_GET_PLUGIN_CONFIG
        )
        self.storage_backend_config = get_config().storage_backend_config

        # 本地持久化存储（与 E2EE store 同目录）
        try:
            path_cls = resolve_core_symbol("Path", Path)
            build_store = resolve_core_symbol(
                "build_e2ee_data_store", _DEFAULT_BUILD_E2EE_DATA_STORE
            )
            store_path = path_cls(self.olm.store.store_path)
            self._storage_store = build_store(
                folder_path=store_path,
                namespace_key=namespace_key or store_path.as_posix(),
                storage_backend_config=self.storage_backend_config,
                json_filename_resolver=self._json_filename_resolver,
                store_name="cross_signing",
            )
        except Exception:
            self._storage_store = None

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
                        request_status = (
                            await self._request_missing_private_keys_from_devices(
                                server_master,
                                server_self_signing,
                                server_user_signing,
                            )
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

                if server_self_signing and server_user_signing:
                    logger.debug("[E2EE-CrossSign] 交叉签名密钥已就绪")
                    return

                if self._master_priv:
                    try:
                        await self._generate_and_upload_keys(
                            force_regen=False,
                            reuse_master=True,
                        )
                    except Exception as e:
                        logger.warning(f"[E2EE-CrossSign] 补全交叉签名密钥失败：{e}")
                        logger.warning("[E2EE-CrossSign] 部分交叉签名功能可能不可用")
                return

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
