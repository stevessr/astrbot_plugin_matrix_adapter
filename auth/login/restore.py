"""Stored OAuth2 session restoration."""


class MatrixAuthRestoreMixin:
    """Restore an existing OAuth2 session or refresh its token."""

    async def _restore_oauth2_session(self) -> bool:
        if not self.access_token:
            return False

        self._log("info", "Attempting to restore OAuth2 session...")

        if not self.oauth2_handler:
            from ..oauth2 import MatrixOAuth2

            self.oauth2_handler = MatrixOAuth2(
                client=self.client,
                homeserver=self.config.homeserver,
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uri=self.config.auth_callback_url,
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
