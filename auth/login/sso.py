"""Matrix SSO login integration."""


class MatrixAuthSsoMixin:
    """Run SSO authentication through the unified webhook."""

    async def _login_via_sso(self, show_qr: bool = False):
        self.login_info.clear()
        self._log("info", "Logging in with SSO...")
        from ..sso import MatrixSSO

        sso = MatrixSSO(
            client=self.client,
            homeserver=self.config.homeserver,
            redirect_uri=self.config.auth_callback_url,
        )

        def url_callback(sso_url: str):
            self.login_info["qrcode"] = sso_url
            self.login_info["qrcode_img_content"] = sso_url
            self.login_info["status"] = "wait"

        try:
            self._active_auth_webhook_handler = sso
            try:
                response = await sso.login(
                    device_name=self.device_name,
                    device_id=self.device_id,
                    show_qr=show_qr,
                    url_callback=url_callback,
                )
            finally:
                if self._active_auth_webhook_handler is sso:
                    self._active_auth_webhook_handler = None
            self.login_info["status"] = "confirmed"
        except Exception as e:
            self.login_info["status"] = "error"
            self.login_info["error"] = str(e)
            raise e

        self.user_id = response.get("user_id")
        if self.user_id:
            self.config.user_id = self.user_id

        device_id = response.get("device_id")
        if device_id:
            self.config.set_device_id(device_id)
        self.access_token = response.get("access_token")
        self.refresh_token = response.get("refresh_token")

        self._log("info", f"✅ Successfully logged in via SSO as {self.user_id}")
        self._save_token()
        self._config_needs_save = True
