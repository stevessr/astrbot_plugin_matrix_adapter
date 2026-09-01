"""OAuth2 login and token refresh integration."""


class MatrixAuthOAuth2Mixin:
    """Run OAuth2 authentication and refresh its session."""

    async def _login_via_oauth2(self):
        self._log("info", "Logging in with OAuth2...")
        self._log("info", "OAuth2 configuration will be auto-discovered from server...")
        self.login_info.clear()
        try:
            from ..oauth2 import MatrixOAuth2

            # A webhook is only required for the authorization-code flow. Matrix
            # v1.18 / MSC4341 allows headless clients to fall back to the device
            # authorization grant when no redirect URI is configured.
            redirect_uri = (
                self.config.auth_callback_url
                if getattr(self.config, "webhook_uuid", None)
                else None
            )
            self.oauth2_handler = MatrixOAuth2(
                client=self.client,
                homeserver=self.config.homeserver,
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uri=redirect_uri,
            )
            self._active_auth_webhook_handler = (
                self.oauth2_handler if redirect_uri else None
            )

            def device_verification_callback(info: dict):
                verification_url = (
                    info.get("verification_uri_complete")
                    or info.get("verification_uri")
                    or ""
                )
                self.login_info["status"] = "wait"
                self.login_info["user_code"] = info.get("user_code")
                self.login_info["verification_uri"] = info.get("verification_uri")
                self.login_info["verification_uri_complete"] = info.get(
                    "verification_uri_complete"
                )
                # Reuse the QR-facing fields already understood by AstrBot's
                # platform login status UI. verification_uri_complete is ideal
                # for QR display when the authorization server supplies it.
                self.login_info["qrcode"] = verification_url
                self.login_info["qrcode_img_content"] = verification_url

            try:
                response = await self.oauth2_handler.login(
                    on_device_verification=device_verification_callback
                )
            finally:
                if self._active_auth_webhook_handler is self.oauth2_handler:
                    self._active_auth_webhook_handler = None

            self.login_info["status"] = "confirmed"
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
            self.login_info["status"] = "error"
            self.login_info["error"] = str(e)
            error_msg = str(e)
            self._log("error", f"❌ OAuth2 login failed: {error_msg}")

            if (
                "authentication configuration" in error_msg.lower()
                or "not supported" in error_msg.lower()
                or "does not advertise" in error_msg.lower()
                or "404" in error_msg
            ):
                self._log(
                    "warning",
                    "OAuth2 auto-discovery/device flow unavailable. Attempting SSO (m.login.sso) fallback...",
                )
                try:
                    await self._login_via_sso()
                    return
                except Exception as sso_error:
                    self._log("error", f"SSO fallback failed: {sso_error}")
                    self._log(
                        "error",
                        "💡 Suggestion: Change matrix_auth_method to 'password' in your configuration "
                        "and provide matrix_user_id and matrix_password.",
                    )

            raise RuntimeError(f"OAuth2 login failed: {e}")
