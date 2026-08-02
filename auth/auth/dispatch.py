"""Authentication method dispatch and reauthentication flow."""


class MatrixAuthDispatchMixin:
    """Dispatch configured authentication methods."""

    def login(self):
        """
        Perform login based on configured authentication method
        Supports: password, token, oauth2
        """
        return self._login_wrapper()

    async def _login_wrapper(self):
        self._device_id_rotated_for_reauth = False
        # Always try to load token first for potential restoration
        self._load_token()

        if self.auth_method == "oauth2":
            if await self._restore_oauth2_session():
                return
            if self.access_token:
                self._reset_device_id_for_reauth("OAuth2 session restore failed")
            await self._login_via_oauth2()
        elif self.auth_method == "qr":
            if self.access_token:
                try:
                    await self._login_via_token()
                    return
                except RuntimeError:
                    self._log(
                        "info",
                        "Stored token expired or invalid, falling back to QR login",
                    )
                    self._reset_device_id_for_reauth(
                        "Stored token invalid before QR login"
                    )

            await self._login_via_qr()
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
                    self._reset_device_id_for_reauth(
                        "Stored token invalid before password login"
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
                        self._reset_device_id_for_reauth(
                            "Stored token invalid before password login"
                        )

                await self._login_via_password()
                self._save_token()
            else:
                raise ValueError(
                    "Either matrix_access_token or matrix_password is required. "
                    "For OAuth2/QR, set matrix_auth_method='oauth2' or 'qr'"
                )
