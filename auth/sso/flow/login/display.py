"""SSO login announcement and QR display."""

from ....oauth2.core import _log
from ...qr import _build_terminal_qr


class MatrixSSOLoginDisplayMixin:
    """Announce the SSO login URL and optional QR code."""

    def _announce_sso_login(
        self,
        sso_url: str,
        url_callback: callable,
        show_qr: bool,
    ) -> None:
        """Emit the login URL via callback and logs."""
        if url_callback:
            url_callback(sso_url)

        _log("info", "=" * 60)
        _log("info", "SSO Authentication Required")
        _log("info", "=" * 60)
        _log("info", f"Please open this URL in your browser:\n\n{sso_url}\n")
        if show_qr:
            terminal_qr = _build_terminal_qr(sso_url)
            if terminal_qr:
                _log("info", "Scan this QR code to continue authentication:")
                _log("info", f"\n{terminal_qr}")
            else:
                _log(
                    "warning",
                    "QR rendering dependency missing. Install 'qrcode' to display terminal QR codes.",
                )
        _log("info", "Waiting for SSO callback...")
        _log("info", "=" * 60)


__all__ = ["MatrixSSOLoginDisplayMixin"]
