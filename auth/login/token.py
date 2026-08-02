"""Access-token login and fallback handling."""


class MatrixAuthTokenMixin:
    """Validate stored tokens and perform configured fallbacks."""

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
            self._reset_device_id_for_reauth(
                "Stored token invalid; password re-login requires a new device"
            )
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
