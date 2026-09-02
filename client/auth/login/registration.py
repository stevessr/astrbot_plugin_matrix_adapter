"""Matrix account registration and login-token operations."""

from typing import Any


class AuthLoginRegistrationMixin:
    """Register accounts and use Matrix registration/login-token helpers."""

    async def register(
        self,
        username: str | None = None,
        password: str | None = None,
        device_name: str | None = None,
        inhibit_login: bool = False,
        auth: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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

    async def check_registration_token(self, token: str) -> bool:
        """Check Matrix v1.2 / MSC3231 registration-token validity.

        This endpoint is unauthenticated and point-in-time only: a token which is
        valid now can still expire before the subsequent registration request.
        """
        if not isinstance(token, str) or not token.strip():
            raise ValueError("token must be a non-empty string")
        response = await self._request(
            "GET",
            "/_matrix/client/v1/register/m.login.registration_token/validity",
            params={"token": token},
            authenticated=False,
        )
        return isinstance(response, dict) and response.get("valid") is True

    async def generate_login_token(
        self,
        auth: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a single-use login token via the stable Matrix endpoint."""
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
