import asyncio
from pathlib import Path
from typing import Literal

from .....storage.backend import (
    build_folder_namespace as _DEFAULT_BUILD_FOLDER_NAMESPACE,
)
from .....storage.paths import MatrixStoragePaths as _DEFAULT_MATRIX_STORAGE_PATHS
from ....constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC,
    DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
)
from ....olm import OlmMachine
from ....store import CryptoStore
from ..compat import resolve_manager_symbol, resolve_plugin_config


class E2EEManagerCoreInitializationConstructorMixin:
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
            password: 用户密码 (可选，用于 UIA)
            proactive_key_exchange: 是否启用主动密钥交换
            key_maintenance_interval: 一次性密钥自动补充的最小间隔（秒）
            otk_threshold_ratio: 触发一次性密钥补充的服务器密钥数量比例（百分比）
            key_share_check_interval: Periodic room-key distribution interval in
                seconds. Zero selects event-driven lazy mode unless proactive key
                exchange is enabled, in which case a 30-second interval is used.
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password

        # 使用 MatrixStoragePaths 生成用户存储目录
        self._store_base_path = Path(store_path)
        storage_paths = resolve_manager_symbol(
            "MatrixStoragePaths",
            _DEFAULT_MATRIX_STORAGE_PATHS,
        )
        self.store_path = storage_paths.get_user_storage_dir(
            str(self._store_base_path), homeserver, user_id
        )
        build_namespace = resolve_manager_symbol(
            "build_folder_namespace",
            _DEFAULT_BUILD_FOLDER_NAMESPACE,
        )
        self._store_namespace = build_namespace(self.store_path, self._store_base_path)

        # Ensure the directory exists
        storage_paths.ensure_directory(self.store_path, treat_as_file=False)
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
        plugin_config = resolve_plugin_config()
        self.storage_backend_config = plugin_config.storage_backend_config
        self.data_storage_backend = self.storage_backend_config.backend
        self.pgsql_dsn = self.storage_backend_config.pgsql_dsn
        self.pgsql_schema = self.storage_backend_config.pgsql_schema
        self.pgsql_table_prefix = self.storage_backend_config.pgsql_table_prefix

        self._store: CryptoStore | None = None
        self._olm: OlmMachine | None = None
        self._verification = None  # SASVerification
        self._key_backup = None  # KeyBackup
        self._cross_signing = None  # CrossSigning
        self._initialized = False
        self._closing = False
        # session_id -> {"@user:server|DEVICEID", ...}
        self._room_key_share_cache: dict[str, set[str]] = {}
        # A single distribution pass per Megolm session prevents duplicate
        # /keys/claim and to-device sends from periodic and event-driven paths.
        self._room_key_share_locks: dict[str, asyncio.Lock] = {}
        # room_id -> (members, monotonic timestamp)
        self._room_members_cache: dict[str, tuple[list[str], float]] = {}
        self._room_members_cache_ttl_sec = DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC
        self._room_history_visibility: dict[str, str] = {}
        self._room_encryption_config: dict[str, dict] = {}
        # throttle one-time key maintenance to avoid frequent uploads
        self._last_otk_maintenance_ts = 0.0
        # 定期密钥分发检查的任务和锁
        self._key_share_check_task: asyncio.Task | None = None
        self._key_share_check_lock = asyncio.Lock()
        # Missing-session requests reuse their Matrix request ID and are throttled.
        self._pending_room_key_requests: dict[tuple[str, str], dict] = {}
        self._room_key_request_lock = asyncio.Lock()
        self._room_key_request_retry_interval_sec = DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC
        self._room_key_request_expiry_sec = DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC
        # m.no_olm MUST be emitted only once per failed peer until an Olm send
        # succeeds. Incoming recovery attempts are independently rate-limited.
        self._no_olm_withheld_sent: set[tuple[str, str]] = set()
        self._olm_recovery_attempts: dict[tuple[str, str], float] = {}
        self._olm_recovery_retry_interval_sec = DEFAULT_OLM_RECOVERY_RETRY_SEC
        self._room_key_withheld: dict[tuple[str, str, str], dict] = {}
