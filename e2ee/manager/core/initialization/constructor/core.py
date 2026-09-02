"""E2EE manager construction entry point."""

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal

from .....constants import DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC


class E2EEManagerCoreInitializationConstructorCoreMixin:
    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        store_path: str | Path,
        homeserver: str,
        auto_verify_mode: Literal[
            "auto_accept", "auto_reject", "manual"
        ] = "auto_accept",
        enable_key_backup: bool = False,
        recovery_key: str = "",
        trust_on_first_use: bool = False,
        password: str | None = None,
        proactive_key_exchange: bool = False,
        key_maintenance_interval: int = 60,
        otk_threshold_ratio: int = 33,
        key_share_check_interval: int = 0,
        oauth_uia_callback: Callable[[dict], Awaitable[None] | None] | None = None,
    ):
        """
        初始化 E2EE 管理器

        Args:
            client: MatrixHTTPClient 实例
            user_id: 用户 ID
            device_id: 设备 ID
            store_path: 加密存储基础路径
            homeserver: Matrix 服务器 URL
            auto_verify_mode: 自动验证模式 (auto_accept/auto_reject/manual)
            enable_key_backup: 是否启用密钥备份
            recovery_key: 用户配置的恢复密钥 (base64)
            trust_on_first_use: 是否自动信任首次使用的设备
            password: 用户密码 (可选，用于 legacy UIA)
            proactive_key_exchange: 是否启用主动密钥交换
            key_maintenance_interval: 一次性密钥自动补充的最小间隔（秒）
            otk_threshold_ratio: 触发一次性密钥补充的服务器密钥数量比例（百分比）
            key_share_check_interval: Periodic room-key distribution interval in
                seconds. Zero selects event-driven lazy mode unless proactive key
                exchange is enabled, in which case a 30-second interval is used.
            oauth_uia_callback: Optional callback invoked with stable ``m.oauth``
                approval metadata (``url`` and ``session``) before polling the
                cross-signing upload for completion.
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password
        self.oauth_uia_callback = oauth_uia_callback

        # 使用 MatrixStoragePaths 生成用户存储目录
        self._init_storage_paths(store_path, homeserver, user_id)

        self.auto_verify_mode = auto_verify_mode
        self.enable_key_backup = enable_key_backup
        self.recovery_key = recovery_key
        self.trust_on_first_use = trust_on_first_use

        # 密钥交换积极性配置
        self.proactive_key_exchange = proactive_key_exchange
        self.key_maintenance_interval = key_maintenance_interval
        self.otk_threshold_ratio = max(1, min(100, otk_threshold_ratio))
        self.key_share_check_interval = max(0, key_share_check_interval)
        if self.proactive_key_exchange and self.key_share_check_interval == 0:
            self.key_share_check_interval = DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC
        self._init_storage_config()
        self._init_runtime_state()
