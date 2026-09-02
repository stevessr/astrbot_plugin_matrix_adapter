"""Matrix account registration and login-token operations."""

from typing import Any


class AuthLoginRegistrationMixin:
    """Register accounts and generate single-use Matrix login tokens."""

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

    async def generate_login_token(
        self,
        auth: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a single-use login token via the stable Matrix endpoint.

        ``POST /_matrix/client/v1/login/get_token`` is a UIA endpoint. Calling
        this method without ``auth`` is useful to obtain the initial 401 UIA
        challenge; callers can then pass the completed UIA object back in.

        The homeserver response contains ``login_token`` and ``expires_in_ms``.
        The token is intentionally not persisted on this client because it is
        for a separate unauthenticated client/device and is single-use.
        """
        data: dict[str, Any] = {}
        if auth is not None:
            if not isinstance(auth, dict):
                raise TypeError("auth must be a mapping")
            data["auth"] = auth
        return await self._request(
            "POST",
            "/_matrix/client/v1/login/get_token",
            data=data,
        )
