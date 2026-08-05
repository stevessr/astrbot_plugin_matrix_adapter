"""Login response application and request orchestration."""

from typing import Any


class AuthLoginCredentialsRequestMixin:
    """Perform a login request and persist the session identity."""

    async def _perform_login(self, data: dict) -> dict[str, Any]:
        response = await self._request(
            "POST", "/_matrix/client/v3/login", data=data, authenticated=False
        )
        self.access_token = response.get("access_token")
        self.user_id = response.get("user_id")
        self.device_id = response.get("device_id")
        return response


__all__ = ["AuthLoginCredentialsRequestMixin"]
