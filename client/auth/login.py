"""Password, token, and account-registration operations."""

from typing import Any

from astrbot.api import logger

from ...constants import LOGIN_TYPE_PASSWORD, LOGIN_TYPE_TOKEN


class AuthLoginMixin:
    """Perform Matrix login and registration flows."""

    async def login_password(
        self,
        user_id: str,
        password: str,
        device_name: str = "AstrBot",
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Login with password

        Args:
            user_id: Matrix user ID
            password: User password
            device_name: Device display name
            device_id: Optional device ID to reuse

        Returns:
            Login response with access_token, device_id, etc.
        """
        data = {
            "type": LOGIN_TYPE_PASSWORD,
            "identifier": {"type": "m.id.user", "user": user_id},
            "password": password,
            "initial_device_display_name": device_name,
        }
        if device_id:
            data["device_id"] = device_id

        try:
            response = await self._request(
                "POST", "/_matrix/client/v3/login", data=data, authenticated=False
            )

            self.access_token = response.get("access_token")
            self.user_id = response.get("user_id")
            self.device_id = response.get("device_id")

            return response
        except Exception as e:
            error_msg = str(e)
            # Provide better diagnostics for HTML error pages
            if "HTML error page" in error_msg or "status: 403" in error_msg:
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
            raise

    async def login_token(
        self,
        token: str,
        device_name: str = "AstrBot",
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Login with a token

        Args:
            token: Login token
            device_name: Device display name
            device_id: Optional device ID to reuse

        Returns:
            Login response with access_token, device_id, etc.
        """
        data = {
            "type": LOGIN_TYPE_TOKEN,
            "token": token,
            "initial_device_display_name": device_name,
        }
        if device_id:
            data["device_id"] = device_id

        response = await self._request(
            "POST", "/_matrix/client/v3/login", data=data, authenticated=False
        )
        self.access_token = response.get("access_token")
        self.user_id = response.get("user_id")
        self.device_id = response.get("device_id")
        return response

    async def register(
        self,
        username: str | None = None,
        password: str | None = None,
        device_name: str | None = None,
        inhibit_login: bool = False,
        auth: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Register a new account

        Args:
            username: Optional localpart
            password: Optional password
            device_name: Optional device display name
            inhibit_login: If True, do not log in after registration
            auth: Optional UIA auth dict

        Returns:
            Registration response
        """
        data: dict[str, Any] = {}
        if username:
            data["username"] = username
        if password:
            data["password"] = password
        if device_name:
            data["initial_device_display_name"] = device_name
        if inhibit_login:
            data["inhibit_login"] = True
        if auth:
            data["auth"] = auth

        response = await self._request(
            "POST", "/_matrix/client/v3/register", data=data, authenticated=False
        )
        if not inhibit_login:
            self.access_token = response.get("access_token")
            self.user_id = response.get("user_id")
            self.device_id = response.get("device_id")
        return response
