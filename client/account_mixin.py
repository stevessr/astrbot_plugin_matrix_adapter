"""
Matrix HTTP Client - Account Mixin
Provides account and 3PID management methods
"""

from typing import Any


class AccountMixin:
    """Account management methods for Matrix client"""

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
        return await self._request("POST", "/_matrix/client/v3/account/password", data=data)

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
        return await self._request("POST", "/_matrix/client/v3/account/deactivate", data=data)

    async def get_3pid(self) -> dict[str, Any]:
        """
        Get linked third-party identifiers

        Returns:
            3PID response
        """
        return await self._request("GET", "/_matrix/client/v3/account/3pid")

    async def add_3pid(self, threepid_creds: dict[str, Any], bind: bool | None = None) -> dict[str, Any]:
        """
        Add a third-party identifier

        Args:
            threepid_creds: 3PID credentials
            bind: Optional bind flag

        Returns:
            Response data
        """
        data: dict[str, Any] = {"threepid_creds": threepid_creds}
        if bind is not None:
            data["bind"] = bind
        return await self._request("POST", "/_matrix/client/v3/account/3pid/add", data=data)

    async def delete_3pid(self, medium: str, address: str) -> dict[str, Any]:
        """
        Delete a third-party identifier

        Args:
            medium: Medium (email/msisdn)
            address: Address

        Returns:
            Response data
        """
        data = {"medium": medium, "address": address}
        return await self._request("POST", "/_matrix/client/v3/account/3pid/delete", data=data)

    async def bind_3pid(self, medium: str, address: str) -> dict[str, Any]:
        """
        Bind a third-party identifier

        Args:
            medium: Medium (email/msisdn)
            address: Address

        Returns:
            Response data
        """
        data = {"medium": medium, "address": address}
        return await self._request("POST", "/_matrix/client/v3/account/3pid/bind", data=data)

    async def unbind_3pid(self, medium: str, address: str) -> dict[str, Any]:
        """
        Unbind a third-party identifier

        Args:
            medium: Medium (email/msisdn)
            address: Address

        Returns:
            Response data
        """
        data = {"medium": medium, "address": address}
        return await self._request("POST", "/_matrix/client/v3/account/3pid/unbind", data=data)
