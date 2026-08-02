"""QR-based authentication entrypoint."""


class MatrixAuthQrMixin:
    """Start QR authentication through the SSO flow."""

    async def _login_via_qr(self):
        self._log("info", "Logging in with QR code...")
        self._log(
            "info",
            "QR login uses m.login.sso + m.login.token flow. "
            "Scan the terminal QR code with a browser or mobile device.",
        )
        await self._login_via_sso(show_qr=True)
