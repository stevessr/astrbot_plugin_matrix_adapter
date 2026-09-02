"""Matrix logout and access-token refresh operations."""

from typing import Any


class AuthSessionLifecycleMixin:
    """End Matrix sessions and refresh access tokens."""

    async def logout(self) -> dict[str, Any]:
        return await self._request("POST", "/_matrix/client/v3/logout")

    async def logout_all(self) -> dict[str, Any]:
        return await self._request("POST", "/_matrix/client/v3/logout/all")

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh a Matrix access token with the required refresh token.

        Matrix v1.5 clarified that ``refresh_token`` is a required request
        field. Reject an empty/non-string value locally rather than issuing a
        malformed unauthenticated refresh request.
        """
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            raise ValueError("refresh_token must be a non-empty string")

        response = await self._request(
            "POST",
            "/_matrix/client/v3/refresh",
            data={"refresh_token": refresh_token},
            authenticated=False,
        )
        if "access_token" in response:
            self.access_token = response["access_token"]
        return response
