"""Matrix password and token login operations."""

from typing import Any


class AuthLoginCredentialsOrchestratorMixin:
    """Perform Matrix password and token login flows."""

    async def login_password(
        self,
        user_id: str,
        password: str,
        device_name: str = "AstrBot",
        device_id: str | None = None,
        *,
        request_refresh_token: bool = True,
    ) -> dict[str, Any]:
        """Login with password and request a refresh token by default."""
        data = self._build_password_login_data(
            user_id,
            password,
            device_name,
            device_id,
            request_refresh_token,
        )

        try:
            return await self._perform_login(data)
        except Exception as e:
            error_msg = str(e)
            if "HTML error page" in error_msg or "status: 403" in error_msg:
                self._log_password_login_diagnostics(error_msg, user_id)
            raise

    async def login_token(
        self,
        token: str,
        device_name: str = "AstrBot",
        device_id: str | None = None,
        *,
        request_refresh_token: bool = True,
    ) -> dict[str, Any]:
        """Login with a login token and request a refresh token by default."""
        data = self._build_token_login_data(
            token,
            device_name,
            device_id,
            request_refresh_token,
        )
        return await self._perform_login(data)


__all__ = ["AuthLoginCredentialsOrchestratorMixin"]
