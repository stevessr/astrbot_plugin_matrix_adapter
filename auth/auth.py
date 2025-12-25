"""
Matrix 登录认证组件（不依赖 matrix-nio）
支持密码、Token 和 OAuth2 认证
"""

import json
from pathlib import Path

from astrbot.api import logger


class MatrixAuth:
    def __init__(self, client, config, token_store_path: str = None):
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

    def _get_token_store_path(self) -> str:
        """Get path for storing auth token"""
        if self.token_store_path:
            return self.token_store_path

        # 使用新的存储路径逻辑
        from ..storage_paths import MatrixStoragePaths

        if self.user_id and self.config.homeserver:
            auth_path = MatrixStoragePaths.get_auth_file_path(
                self.config.store_path, self.config.homeserver, self.user_id
            )
            # 确保目录存在
            MatrixStoragePaths.ensure_directory(auth_path)
            return str(auth_path)

        # 回退到旧路径（兼容性）
        sanitized_user = (
            self.user_id.replace(":", "_").replace("@", "")
            if self.user_id
            else "unknown"
        )
        return str(Path("data") / f"matrix_auth_{sanitized_user}.json")

    def _save_token(self):
        """Save access token to disk"""
        if not self.access_token:
            return

        try:
            path = self._get_token_store_path()
            Path(path).parent.mkdir(parents=True, exist_ok=True)

            data = {
                "access_token": self.access_token,
                "device_id": self.device_id,
                "user_id": self.user_id,
                "home_server": self.config.homeserver,
            }
            if self.refresh_token:
                data["refresh_token"] = self.refresh_token

            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._log("info", f"Saved auth token to {path}")
        except Exception as e:
            self._log("error", f"Failed to save auth token: {e}")

    def _load_token(self) -> bool:
        """Load access token from disk"""
        try:
            path = self._get_token_store_path()
            if not Path(path).exists():
                return False

            with open(path) as f:
                data = json.load(f)

            # Verify homeserver matches
            if data.get("home_server") != self.config.homeserver:
                self._log(
                    "info", "Stored token is for a different homeserver, ignoring"
                )
                return False

            self.access_token = data.get("access_token")
            device_id = data.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self.refresh_token = data.get("refresh_token")

            if self.access_token:
                self._log("info", f"Loaded auth token from {path}")
                return True
            return False
        except Exception as e:
            self._log("error", f"Failed to load auth token: {e}")
            return False

    def login(self):
        """
        Perform login based on configured authentication method
        Supports: password, token, oauth2
        """
        return self._login_wrapper()

    async def _login_wrapper(self):
        if self.auth_method == "oauth2":
            await self._login_via_oauth2()
        elif self.auth_method == "token":
            await self._login_via_token()
        elif self.auth_method == "password":
            # Try to load token first
            if self._load_token():
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
                # Try to load token first
                if self._load_token():
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

    async def _login_via_password(self):
        self._log("info", "Logging in with password...")

        # First, check what login flows are supported
        try:
            self._log(
                "info",
                f"Checking supported login methods from {self.config.homeserver}...",
            )
            flows_response = await self.client.get_login_flows()
            flows = flows_response.get("flows", [])
            supported_types = [flow.get("type") for flow in flows]

            self._log("info", f"Server supports login types: {supported_types}")

            if "m.login.password" not in supported_types:
                self._log(
                    "error",
                    f"Server does not support password login! Supported methods: {supported_types}\n"
                    f"You may need to use a different authentication method like 'token' or 'oauth2'",
                )
        except Exception as flow_error:
            self._log(
                "error",
                f"Failed to check login flows: {flow_error}\n"
                f"This usually means the homeserver URL is incorrect or unreachable.\n"
                f"Current homeserver: {self.config.homeserver}",
            )
            # Continue anyway to get the actual error from login attempt

        try:
            response = await self.client.login_password(
                user_id=self.user_id,
                password=self.password,
                device_name=self.device_name,
                device_id=self.device_id,
            )
            self.user_id = response.get("user_id")
            device_id = response.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self.access_token = response.get("access_token")
            self.refresh_token = response.get("refresh_token")
            self._log("info", f"Successfully logged in as {self.user_id}")
        except Exception as e:
            self._log("error", f"Matrix password login failed: {e}")
            raise RuntimeError(f"Password login failed: {e}")

    async def _login_via_token(self):
        self._log("info", "Logging in with access token...")
        original_error = None

        try:
            # 尝试使用现有 token 登录
            self.client.restore_login(
                user_id=self.user_id,
                device_id=self.device_id,
                access_token=self.access_token,
            )

            # 验证 token 有效性
            sync_response = await self.client.sync(timeout=0, full_state=False)
            if "error" in sync_response or "errcode" in sync_response:
                error_msg = sync_response.get("error", "Unknown error")
                raise RuntimeError(f"Token validation failed: {error_msg}")

            # 获取用户信息
            whoami = await self.client.whoami()
            self.user_id = whoami.get("user_id", self.user_id)
            device_id = whoami.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self._log("info", f"Successfully logged in as {self.user_id}")
            return

        except Exception as e:
            original_error = e
            error_str = str(e)
            self._log("error", f"Token login failed: {error_str}")

            # 检查是否是 token 无效错误
            is_token_invalid = (
                "M_UNKNOWN_TOKEN" in error_str
                or "Unknown access token" in error_str
                or "Token validation failed" in error_str
            )

            if not is_token_invalid:
                # 非 token 无效错误，直接抛出
                raise RuntimeError(
                    f"Token login failed: {error_str}"
                ) from original_error

        # 尝试刷新 token
        if self.refresh_token:
            self._log("info", "Attempting to refresh access token...")
            try:
                refresh_response = await self.client.refresh_access_token(
                    self.refresh_token
                )
                self.access_token = refresh_response.get("access_token")
                if "refresh_token" in refresh_response:
                    self.refresh_token = refresh_response.get("refresh_token")
                self._save_token()
                self._log("info", "Successfully refreshed access token")

                # 使用新 token 重新尝试登录
                await self._login_via_token()
                return

            except Exception as refresh_error:
                self._log("error", f"Token refresh failed: {refresh_error}")

        # 尝试使用密码重新登录
        if self.password:
            self._log("info", "Attempting password re-login...")
            try:
                await self._login_via_password()
                self._save_token()
                self._log("info", "Successfully re-logged in with password")
                return

            except Exception as password_error:
                self._log("error", f"Password re-login failed: {password_error}")

        # 所有认证方法都失败了
        failure_reasons = []
        failure_reasons.append("Token validation failed")
        if self.refresh_token:
            failure_reasons.append("Token refresh failed")
        if self.password:
            failure_reasons.append("Password re-login failed")
        else:
            failure_reasons.append("No password available for fallback")

        error_msg = f"Authentication failed: {'; '.join(failure_reasons)}. Original error: {original_error}"
        self._log("error", error_msg)
        raise RuntimeError(error_msg) from original_error

    async def _login_via_oauth2(self):
        """
        Login using OAuth2 authorization code flow
        All OAuth2 configuration is auto-discovered from the homeserver
        """
        self._log("info", "Logging in with OAuth2...")
        self._log("info", "OAuth2 configuration will be auto-discovered from server...")
        try:
            from .oauth2 import MatrixOAuth2

            # Initialize OAuth2 handler - all config auto-discovered
            self.oauth2_handler = MatrixOAuth2(
                client=self.client,
                homeserver=self.config.homeserver,
                callback_port=self.config.oauth2_callback_port,
                callback_host=self.config.oauth2_callback_host,
            )

            # Perform OAuth2 login flow (includes discovery and registration)
            response = await self.oauth2_handler.login()

            # Update credentials
            self.user_id = response.get("user_id")
            device_id = response.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self.access_token = response.get("access_token")
            self.refresh_token = response.get("refresh_token")

            self._log("info", f"✅ Successfully logged in via OAuth2 as {self.user_id}")
            self._config_needs_save = True

        except Exception as e:
            error_msg = str(e)
            self._log("error", f"❌ OAuth2 login failed: {error_msg}")

            # Provide helpful guidance
            if "not supported" in error_msg.lower() or "404" in error_msg:
                self._log(
                    "error",
                    "💡 Suggestion: Change matrix_auth_method to 'password' in your configuration "
                    "and provide matrix_user_id and matrix_password.",
                )

            raise RuntimeError(f"OAuth2 login failed: {e}")

    async def refresh_oauth2_token(self):
        """
        Refresh OAuth2 access token using refresh token
        """
        if not self.oauth2_handler:
            raise RuntimeError("OAuth2 handler not initialized")

        try:
            self._log("info", "Refreshing OAuth2 access token...")
            response = await self.oauth2_handler.refresh_access_token()

            # Update credentials
            self.access_token = response.get("access_token")
            if "refresh_token" in response:
                self.refresh_token = response["refresh_token"]

            self._log("info", "OAuth2 token refreshed successfully")
            self._config_needs_save = True

        except Exception as e:
            self._log("error", f"Failed to refresh OAuth2 token: {e}")
            raise RuntimeError(f"Token refresh failed: {e}")

    async def refresh_token(self) -> bool:
        """
        Unified method to refresh access token regardless of auth method
        Returns True if successful, False otherwise
        """
        try:
            if self.auth_method == "oauth2":
                await self.refresh_oauth2_token()
                self._save_token()
                return True
            elif self.refresh_token:
                # Standard Matrix token refresh
                self._log("info", "Refreshing standard Matrix access token...")
                response = await self.client.refresh_access_token(self.refresh_token)

                self.access_token = response.get("access_token")
                if "refresh_token" in response:
                    self.refresh_token = response.get("refresh_token")

                self._save_token()
                self._log("info", "Standard token refreshed successfully")
                return True
            else:
                self._log("error", "No refresh token available to refresh session")
                return False
        except Exception as e:
            self._log("error", f"Failed to refresh token: {e}")
            return False
