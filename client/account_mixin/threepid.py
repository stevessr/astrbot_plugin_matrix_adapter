"""Matrix third-party identifier management operations."""

from typing import Any


class AccountThreepidMixin:
    async def get_3pid(self) -> dict[str, Any]:
        """
        Get linked third-party identifiers

        Returns:
            3PID response
        """
        return await self._request("GET", "/_matrix/client/v3/account/3pid")

    async def add_3pid(
        self, threepid_creds: dict[str, Any], bind: bool | None = None
    ) -> dict[str, Any]:
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
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/add", data=data
        )

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
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/delete", data=data
        )

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
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/bind", data=data
        )

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
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/unbind", data=data
        )
