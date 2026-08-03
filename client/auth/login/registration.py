"""Matrix account registration operations."""

from typing import Any


class AuthLoginRegistrationMixin:
    """Register new Matrix accounts."""

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
