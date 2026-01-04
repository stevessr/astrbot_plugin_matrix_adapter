"""
Matrix HTTP Client - Authentication Mixin
Provides login, token management, and authentication methods
"""

from typing import Any

from astrbot.api import logger

from ..constants import DEFAULT_TIMEOUT_MS_30000


class AuthMixin:
    """Authentication methods for Matrix client"""

    async def get_versions(self) -> dict[str, Any]:
        """
        Get supported Matrix client-server API versions

        Returns:
            Versions response
        """
        return await self._request("GET", "/_matrix/client/versions", authenticated=False)

    async def get_capabilities(self) -> dict[str, Any]:
        """
        Get server capabilities

        Returns:
            Capabilities response
        """
        return await self._request("GET", "/_matrix/client/v3/capabilities")

    async def get_login_flows(self) -> dict[str, Any]:
        """
        Get supported login flows from the server

        Returns:
            Response with supported login flows
        """
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )

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
            "type": "m.login.password",
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
            "type": "m.login.token",
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

    async def logout(self) -> dict[str, Any]:
        """
        Logout the current device

        Returns:
            Empty dict on success
        """
        return await self._request("POST", "/_matrix/client/v3/logout")

    async def logout_all(self) -> dict[str, Any]:
        """
        Logout all devices

        Returns:
            Empty dict on success
        """
        return await self._request("POST", "/_matrix/client/v3/logout/all")

    def restore_login(
        self, user_id: str, access_token: str, device_id: str | None = None
    ):
        """
        Restore login session with access token

        Args:
            user_id: Matrix user ID
            access_token: Access token from previous login
            device_id: Device ID (optional)
        """
        self.user_id = user_id
        self.access_token = access_token
        self.device_id = device_id

    async def whoami(self) -> dict[str, Any]:
        """
        Get information about the current user

        Returns:
            User information including user_id and device_id
        """
        return await self._request("GET", "/_matrix/client/v3/account/whoami")

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh access token using a refresh token

        Args:
            refresh_token: Refresh token from previous login

        Returns:
            Response with new access_token and optionally a new refresh_token
        """
        endpoint = "/_matrix/client/v3/refresh"
        data = {"refresh_token": refresh_token}

        response = await self._request("POST", endpoint, data=data, authenticated=False)

        # Update client with new access token
        if "access_token" in response:
            self.access_token = response["access_token"]

        return response

    async def sync(
        self,
        since: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_MS_30000,
        full_state: bool = False,
        filter_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Sync with the Matrix server

        Args:
            since: Sync batch token from previous sync
            timeout: Timeout in milliseconds
            full_state: Whether to return full state
            filter_id: Filter ID for filtering events

        Returns:
            Sync response
        """
        params = {"timeout": timeout}
        if since:
            params["since"] = since
        if full_state:
            params["full_state"] = "true"
        if filter_id:
            params["filter"] = filter_id

        response = await self._request("GET", "/_matrix/client/v3/sync", params=params)

        # Log to_device events
        to_device = response.get("to_device", {}).get("events", [])
        if to_device:
            logger.info(
                f"SYNC: Received {len(to_device)} to_device events: {[e.get('type') for e in to_device]}"
            )

        # Store next_batch for future syncs
        self._next_batch = response.get("next_batch")

        return response

    async def create_filter(self, user_id: str, filter_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a sync filter for a user

        Args:
            user_id: Matrix user ID
            filter_data: Filter definition

        Returns:
            Response with filter_id
        """
        endpoint = f"/_matrix/client/v3/user/{user_id}/filter"
        return await self._request("POST", endpoint, data=filter_data)

    async def get_filter(self, user_id: str, filter_id: str) -> dict[str, Any]:
        """
        Get a sync filter definition

        Args:
            user_id: Matrix user ID
            filter_id: Filter ID

        Returns:
            Filter definition
        """
        endpoint = f"/_matrix/client/v3/user/{user_id}/filter/{filter_id}"
        return await self._request("GET", endpoint)
