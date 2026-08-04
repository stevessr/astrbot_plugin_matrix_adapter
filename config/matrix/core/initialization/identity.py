"""Matrix identity and authentication configuration state."""

from astrbot.api import logger

from .....storage.stores.device import MatrixDeviceManager


class MatrixConfigIdentityInitializationMixin:
    """Initialize identity and authentication configuration fields."""

    def _initialize_identity_state(self) -> None:
        self.homeserver = str(
            self.config.get("matrix_homeserver", "https://matrix.org") or ""
        ).strip()
        if not self.homeserver:
            self.homeserver = "https://matrix.org"
        self.user_id = str(self.config.get("matrix_user_id", "") or "").strip() or None
        self.password = self.config.get("matrix_password")
        self.access_token = (
            str(self.config.get("matrix_access_token", "") or "").strip() or None
        )
        # Supported methods: password, token, oauth2, qr
        self.auth_method = (
            str(self.config.get("matrix_auth_method", "password") or "password")
            .strip()
            .lower()
        )
        self.device_name = (
            str(self.config.get("matrix_device_name", "AstrBot") or "AstrBot").strip()
            or "AstrBot"
        )
        self.webhook_uuid = (
            str(self.config.get("webhook_uuid", "") or "").strip() or None
        )

        # 设备 ID 现在由 DeviceManager 管理，不再支持手动配置
        # 如果配置中有旧的 device_id，忽略它并记录警告
        if self.config.get("matrix_device_id"):
            logger.warning(
                "matrix_device_id 配置选项已弃用，设备 ID 现在由系统自动生成和管理",
                extra={"plugin_tag": "matrix", "short_levelname": "WARN"},
            )
            # 从内部配置副本中移除旧的 device_id，不影响原始配置
            del self.config["matrix_device_id"]

        # 初始化设备管理器（延迟到有 user_id 时）
        self._device_manager: MatrixDeviceManager | None = None
        self._device_id: str | None = None

        # OAuth2 configuration - all parameters auto-discovered from server
        # Only refresh_token is stored locally (auto-saved after login)
        self.refresh_token = (
            str(self.config.get("matrix_refresh_token", "") or "").strip() or None
        )
