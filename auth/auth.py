"""
Matrix 登录认证组件（不依赖 matrix-nio）
支持密码、Token 和 OAuth2 认证
"""

from astrbot.api import logger

from .auth_login import MatrixAuthLogin
from .auth_store import MatrixAuthStore


class MatrixAuth(MatrixAuthStore, MatrixAuthLogin):
    def __init__(self, client, config, token_store_path: str):
        self.client = client
        self.config = config
        self.user_id = config.user_id
        # device_id 现在通过配置类的属性获取，会自动生成或从存储中恢复
        # 不再设置 self.device_id，直接使用 config.device_id 属性
        self.password = config.password
        self.access_token = config.access_token
        self.auth_method = config.auth_method
        self.device_name = config.device_name
        self.token_store_path = token_store_path
        self._config_needs_save = False

        # OAuth2 specific attributes
        # All OAuth2 configuration is auto-discovered from server
        self.refresh_token: str | None = getattr(config, "refresh_token", None)
        self.client_id: str | None = None
        self.client_secret: str | None = None
        self.oauth2_handler = None

    def _log(self, level, msg):
        extra = {"plugin_tag": "matrix", "short_levelname": level[:4].upper()}
        if level == "info":
            logger.info(msg, extra=extra)
        elif level == "error":
            logger.error(msg, extra=extra)

    @property
    def device_id(self) -> str:
        """获取设备 ID"""
        return self.config.device_id

    def login(self):
        """
        Perform login based on configured authentication method
        Supports: password, token, oauth2
        """
        return self._login_wrapper()

    async def _login_wrapper(self):
        # Always try to load token first for potential restoration
        self._load_token()

        if self.auth_method == "oauth2":
            if await self._restore_oauth2_session():
                return
            await self._login_via_oauth2()
        elif self.auth_method == "token":
            await self._login_via_token()
        elif self.auth_method == "password":
            # Token loaded at start of function
            if self.access_token:
                try:
                    await self._login_via_token()
                    return
                except RuntimeError:
                    self._log(
                        "info",
                        "Stored token expired or invalid, falling back to password login",
                    )

            await self._login_via_password()
            self._save_token()
        else:
            # Auto-detect authentication method
            if self.access_token:
                await self._login_via_token()
            elif self.password:
                # Token loaded at start of function
                if self.access_token:
                    try:
                        await self._login_via_token()
                        return
                    except RuntimeError:
                        self._log(
                            "info",
                            "Stored token expired or invalid, falling back to password login",
                        )

                await self._login_via_password()
                self._save_token()
            else:
                raise ValueError(
                    "Either matrix_access_token or matrix_password is required. "
                    "For OAuth2, set matrix_auth_method='oauth2'"
                )
