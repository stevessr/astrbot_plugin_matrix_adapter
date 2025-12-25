"""
Matrix 登录认证组件（不依赖 matrix-nio）
支持密码、Token 和 OAuth2 认证
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("astrbot.matrix.auth")


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
        try:
            self.client.restore_login(
                user_id=self.user_id,
                device_id=self.device_id,
                access_token=self.access_token,
            )
            # Validate token by doing a quick sync or whoami
            sync_response = await self.client.sync(timeout=0, full_state=False)
            if "error" in sync_response or "errcode" in sync_response:
                error_msg = sync_response.get("error", "Unknown error")
                raise RuntimeError(f"Token validation failed: {error_msg}")

            whoami = await self.client.whoami()
            self.user_id = whoami.get("user_id", self.user_id)
            device_id = whoami.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self._log("info", f"Successfully logged in as {self.user_id}")
        except Exception as e:
            error_str = str(e)
            # Try to refresh token if we have a refresh token
            if "M_UNKNOWN_TOKEN" in error_str or "Unknown access token" in error_str:
                if self.refresh_token:
                    self._log("info", "Access token expired, attempting to refresh...")
                    try:
                        refresh_response = await self.client.refresh_access_token(
                            self.refresh_token
                        )
                        self.access_token = refresh_response.get("access_token")
                        # Update refresh token if a new one is provided
                        if "refresh_token" in refresh_response:
                            self.refresh_token = refresh_response.get("refresh_token")
                        self._save_token()
                        self._log("info", "Successfully refreshed access token")
                        # Retry login with new token
                        await self._login_via_token()
                        return
                    except Exception as refresh_error:
                        self._log(
                            "error",
                            f"Token refresh failed: {refresh_error}",
                        )
                # No refresh token or refresh failed
                # Try password re-login if password is available
                if self.password:
                    self._log(
                        "info",
                        "Access token invalid and refresh failed. Attempting password re-login...",
                    )
                    try:
                        await self._login_via_password()
                        self._save_token()
                        self._log("info", "Successfully re-logged in with password")
                        return
                    except Exception as password_error:
                        self._log(
                            "error",
                            f"Password re-login also failed: {password_error}",
                        )
                        # Fall through to fatal error

                # No password available or password login also failed - panic
                self._log(
                    "error",
                    f"FATAL: Access token is invalid or expired and all recovery methods failed. Error: {e}",
                )
                import sys

                sys.exit(1)
            self._log("error", f"Token validation failed: {e}")
            raise RuntimeError(f"Token validation failed: {e}")

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
