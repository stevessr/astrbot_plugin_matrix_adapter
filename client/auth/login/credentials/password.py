"""Password login payload construction and diagnostics."""

from astrbot.api import logger

from .....constants import LOGIN_TYPE_PASSWORD


class AuthLoginCredentialsPasswordMixin:
    """Build password login payloads and diagnose failures."""

    def _build_password_login_data(
        self,
        user_id: str,
        password: str,
        device_name: str,
        device_id: str | None,
        request_refresh_token: bool = True,
    ) -> dict:
        data = {
            "type": LOGIN_TYPE_PASSWORD,
            "identifier": {"type": "m.id.user", "user": user_id},
            "password": password,
            "initial_device_display_name": device_name,
            # Matrix v1.3 / MSC2918: refresh tokens are opt-in at login.
            "refresh_token": bool(request_refresh_token),
        }
        if device_id:
            data["device_id"] = device_id
        return data

    def _log_password_login_diagnostics(self, error_msg: str, user_id: str) -> None:
        logger.error(
            f"Login failed with HTML error page. This usually means:\n"
            f"  1. The homeserver URL is incorrect (currently: {self.homeserver})\n"
            f"  2. The server URL points to a web interface, not the API\n"
            f"  3. The /login endpoint is disabled or requires additional authentication\n"
            f"  4. There's a reverse proxy/firewall blocking API access\n"
            f"\n"
            f"Attempted URL: {self.homeserver}/_matrix/client/v3/login\n"
            f"User ID: {user_id}\n"
            f"\n"
            f"Troubleshooting:\n"
            f"  - Verify your homeserver URL is correct (should end in the domain, e.g., https://matrix.example.com)\n"
            f"  - Try accessing {self.homeserver}/_matrix/client/versions in a browser\n"
            f"  - Check if your server requires a different login method (SSO, OAuth2, etc.)\n"
            f"  - Consult your server administrator about password login availability"
        )


__all__ = ["AuthLoginCredentialsPasswordMixin"]
