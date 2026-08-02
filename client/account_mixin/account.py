"""Matrix account password and deactivation operations."""

from typing import Any


class AccountOperationsMixin:
    async def change_password(
        self, new_password: str, auth: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Change account password

        Args:
            new_password: New password
            auth: Optional UIA auth dict

        Returns:
            Response data
        """
        data: dict[str, Any] = {"new_password": new_password}
        if auth:
            data["auth"] = auth
        return await self._request(
            "POST", "/_matrix/client/v3/account/password", data=data
        )

    async def deactivate_account(
        self, auth: dict[str, Any] | None = None, erase: bool | None = None
    ) -> dict[str, Any]:
        """
        Deactivate account

        Args:
            auth: Optional UIA auth dict
            erase: Optional erase flag

        Returns:
            Response data
        """
        data: dict[str, Any] = {}
        if auth:
            data["auth"] = auth
        if erase is not None:
            data["erase"] = erase
        return await self._request(
            "POST", "/_matrix/client/v3/account/deactivate", data=data
        )
