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
        data = self._build_password_login_data(
            user_id,
            password,
            device_name,
            device_id,
        )

        try:
            return await self._perform_login(data)
        except Exception as e:
            error_msg = str(e)
            # Provide better diagnostics for HTML error pages
            if "HTML error page" in error_msg or "status: 403" in error_msg:
                self._log_password_login_diagnostics(error_msg, user_id)
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
        data = self._build_token_login_data(
            token,
            device_name,
            device_id,
        )
        return await self._perform_login(data)


__all__ = ["AuthLoginCredentialsOrchestratorMixin"]
