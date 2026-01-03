"""
Matrix authentication flows.
"""


class MatrixAuthLogin:
    """Mixin providing login/refresh flows."""

    async def _restore_oauth2_session(self) -> bool:
        if not self.access_token:
            return False

        self._log("info", "Attempting to restore OAuth2 session...")

        if not self.oauth2_handler:
            from .oauth2 import MatrixOAuth2

            self.oauth2_handler = MatrixOAuth2(
                client=self.client,
                homeserver=self.config.homeserver,
                client_id=self.client_id,
                client_secret=self.client_secret,
                callback_port=self.config.oauth2_callback_port,
                callback_host=self.config.oauth2_callback_host,
            )

        try:
            self.client.restore_login(
                user_id=self.user_id,
                device_id=self.device_id,
                access_token=self.access_token,
            )

            whoami = await self.client.whoami()
            user_id = whoami.get("user_id")
            if user_id:
                self.user_id = user_id
                self.config.user_id = user_id

            self._log("info", f"Restored OAuth2 session for {self.user_id}")
            return True

        except Exception as e:
            self._log("info", f"Stored Access Token invalid: {e}")

            if self.refresh_token:
                self._log("info", "Attempting to refresh OAuth2 token...")
                if await self.refresh_session():
                    try:
                        whoami = await self.client.whoami()
                        if whoami.get("user_id"):
                            self.user_id = whoami.get("user_id")
                            self.config.user_id = self.user_id
                    except Exception as e:
                        self._log(
                            "warning", f"Could not verify user after refresh: {e}"
                        )

                    self._log("info", "OAuth2 session restored via refresh")
                    return True

        return False

    async def _login_via_password(self):
        self._log("info", "Logging in with password...")

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
            self.client.restore_login(
                user_id=self.user_id,
                device_id=self.device_id,
                access_token=self.access_token,
            )

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
            return

        except Exception as e:
            original_error = e
            error_str = str(e)
            self._log("error", f"Token login failed: {error_str}")

            is_token_invalid = (
                "M_UNKNOWN_TOKEN" in error_str
                or "Unknown access token" in error_str
                or "Token validation failed" in error_str
            )

            if not is_token_invalid:
                raise RuntimeError(
                    f"Token login failed: {error_str}"
                ) from original_error

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

                await self._login_via_token()
                return

            except Exception as refresh_error:
                self._log("error", f"Token refresh failed: {refresh_error}")

        if self.password:
            self._log("info", "Attempting password re-login...")
            try:
                await self._login_via_password()
                self._save_token()
                self._log("info", "Successfully re-logged in with password")
                return

            except Exception as password_error:
                self._log("error", f"Password re-login failed: {password_error}")

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
        self._log("info", "Logging in with OAuth2...")
        self._log("info", "OAuth2 configuration will be auto-discovered from server...")
        try:
            from .oauth2 import MatrixOAuth2

            self.oauth2_handler = MatrixOAuth2(
                client=self.client,
                homeserver=self.config.homeserver,
                client_id=self.client_id,
                client_secret=self.client_secret,
                callback_port=self.config.oauth2_callback_port,
                callback_host=self.config.oauth2_callback_host,
            )

            response = await self.oauth2_handler.login()

            self.user_id = response.get("user_id")
            if self.user_id:
                self.config.user_id = self.user_id

            device_id = response.get("device_id")
            if device_id:
                self.config.set_device_id(device_id)
            self.access_token = response.get("access_token")
            self.refresh_token = response.get("refresh_token")

            if self.oauth2_handler.client_id:
                self.client_id = self.oauth2_handler.client_id
            if self.oauth2_handler.client_secret:
                self.client_secret = self.oauth2_handler.client_secret

            self._log("info", f"✅ Successfully logged in via OAuth2 as {self.user_id}")
            self._save_token()
            self._config_needs_save = True

        except Exception as e:
            error_msg = str(e)
            self._log("error", f"❌ OAuth2 login failed: {error_msg}")

            if "not supported" in error_msg.lower() or "404" in error_msg:
                self._log(
                    "error",
                    "💡 Suggestion: Change matrix_auth_method to 'password' in your configuration "
                    "and provide matrix_user_id and matrix_password.",
                )

            raise RuntimeError(f"OAuth2 login failed: {e}")

    async def refresh_oauth2_token(self):
        if not self.oauth2_handler:
            raise RuntimeError("OAuth2 handler not initialized")

        try:
            self._log("info", "Refreshing OAuth2 access token...")
            response = await self.oauth2_handler.refresh_access_token()

            self.access_token = response.get("access_token")
            if "refresh_token" in response:
                self.refresh_token = response["refresh_token"]

            self.client.access_token = self.access_token

            self._log("info", "OAuth2 token refreshed successfully")
            self._config_needs_save = True

        except Exception as e:
            self._log("error", f"Failed to refresh OAuth2 token: {e}")
            raise RuntimeError(f"Token refresh failed: {e}")

    async def refresh_session(self) -> bool:
        try:
            if self.auth_method == "oauth2":
                await self.refresh_oauth2_token()
                self._save_token()
                return True
            elif self.refresh_token:
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
