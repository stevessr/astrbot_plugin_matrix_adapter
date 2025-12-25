"""
Matrix 配置与初始化组件
"""

from astrbot.api import logger

from .constants import DEFAULT_TIMEOUT_MS_30000
from .device_manager import MatrixDeviceManager


class MatrixConfig:
    def __init__(self, config: dict):
        """Initialize Matrix configuration.

        Supported authentication methods: 'password', 'token', and 'oauth2'.
        """
        self.config = config or {}
        self.homeserver = self.config.get("matrix_homeserver", "https://matrix.org")
        self.user_id = self.config.get("matrix_user_id")
        self.password = self.config.get("matrix_password")
        self.access_token = self.config.get("matrix_access_token")
        # Supported methods: password, token, oauth2
        self.auth_method = self.config.get("matrix_auth_method", "password")
        self.device_name = self.config.get("matrix_device_name", "AstrBot")

        # 设备 ID 现在由 DeviceManager 管理，不再支持手动配置
        # 如果配置中有旧的 device_id，忽略它并记录警告
        if self.config.get("matrix_device_id"):
            logger.warning(
                "matrix_device_id 配置选项已弃用，设备 ID 现在由系统自动生成和管理",
                extra={"plugin_tag": "matrix", "short_levelname": "WARN"},
            )
            # 从配置中移除旧的 device_id
            del self.config["matrix_device_id"]

        # 初始化设备管理器（延迟到有 user_id 时）
        self._device_manager: MatrixDeviceManager = None
        self._device_id: str = None

        # OAuth2 configuration - all parameters auto-discovered from server
        # Only refresh_token is stored locally (auto-saved after login)
        self.refresh_token = self.config.get("matrix_refresh_token")

        # Ensure these attributes exist for other components
        self.store_path = self.config.get("matrix_store_path", "./data/matrix_store")
        self.auto_join_rooms = self.config.get("matrix_auto_join_rooms", True)
        self.sync_timeout = self.config.get(
            "matrix_sync_timeout", DEFAULT_TIMEOUT_MS_30000
        )

        # 嘟文串（Threading）配置
        # 当启用时，回复消息会创建/加入线程而非普通的时间线回复
        # 这是一个试验性功能，可能不是所有 Matrix 客户端都支持
        self.enable_threading = self.config.get("matrix_enable_threading", False)

        # E2EE 端到端加密配置（试验性）
        # 启用后 Bot 可以在加密房间中接收和发送消息
        self.enable_e2ee = self.config.get("matrix_enable_e2ee", False)
        self.e2ee_store_path = self.config.get(
            "matrix_e2ee_store_path", "./data/matrix_e2ee"
        )
        # 自动验证模式：auto_accept (自动接受) / auto_reject (自动拒绝) / manual (手动)
        # 无论哪种模式都会打印详细的验证日志
        self.e2ee_auto_verify = self.config.get(
            "matrix_e2ee_auto_verify", "auto_accept"
        )
        # 是否自动信任首次使用的设备 (Trust On First Use)
        # 如果启用，当收到未知设备的验证请求且模式为 auto_accept 时，将自动接受验证
        self.e2ee_trust_on_first_use = self.config.get(
            "matrix_e2ee_trust_on_first_use", False
        )
        # 是否启用密钥备份
        self.e2ee_key_backup = self.config.get("matrix_e2ee_key_backup", False)
        # 用户手动配置的恢复密钥（推荐 Matrix Base58 恢复密钥，兼容 Base64 32 字节密钥）
        # 如果为空，将自动生成新密钥并在日志中输出
        self.e2ee_recovery_key = self.config.get("matrix_e2ee_recovery_key", "")

        # 媒体文件缓存目录，默认为 ./data/temp/matrix_media
        self.media_cache_dir = self.config.get(
            "matrix_media_cache_dir", "./data/temp/matrix_media"
        )

        self._validate()

    @property
    def device_id(self) -> str:
        """获取设备 ID，如果不存在则自动生成"""
        if self._device_id is None:
            self._ensure_device_manager()
            self._device_id = self._device_manager.get_or_create_device_id()
        return self._device_id

    def _ensure_device_manager(self):
        """确保设备管理器已初始化"""
        if self._device_manager is None and self.user_id:
            store_path = self.config.get("matrix_store_path", "./data/matrix_store")
            self._device_manager = MatrixDeviceManager(
                user_id=self.user_id, homeserver=self.homeserver, store_path=store_path
            )

    def set_device_id(self, device_id: str):
        """设置设备 ID"""
        self._ensure_device_manager()
        self._device_manager.set_device_id(device_id)
        self._device_id = device_id

    def reset_device_id(self) -> str:
        """重置设备 ID（生成新的设备 ID）"""
        self._ensure_device_manager()
        self._device_id = self._device_manager.reset_device_id()
        return self._device_id

    def _validate(self):
        if not self.user_id and self.auth_method != "oauth2":
            raise ValueError(
                "matrix_user_id is required in configuration. Format: @username:homeserver.com"
            )
        if not self.homeserver:
            raise ValueError(
                "matrix_homeserver is required in configuration. Example: https://matrix.org"
            )

        valid_auth_methods = ["password", "token", "oauth2"]
        if self.auth_method not in valid_auth_methods:
            raise ValueError(
                f"Invalid matrix_auth_method: {self.auth_method}. Must be one of: {', '.join(valid_auth_methods)}"
            )

        if self.auth_method == "password" and not self.password:
            raise ValueError(
                "matrix_password is required when matrix_auth_method='password'"
            )

        if self.auth_method == "token" and not self.access_token:
            raise ValueError(
                "matrix_access_token is required when matrix_auth_method='token'"
            )

        # OAuth2: client_id is now optional (can be auto-registered if server supports it)
        # No strict validation needed for OAuth2 mode
