"""Password-based Matrix login."""


class MatrixAuthPasswordMixin:
    """Authenticate with Matrix user credentials."""

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
