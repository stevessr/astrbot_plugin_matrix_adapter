"""Standard and OAuth2 session refresh operations."""


class MatrixAuthRefreshMixin:
    """Refresh active authentication sessions."""

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
