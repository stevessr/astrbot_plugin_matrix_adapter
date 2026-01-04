"""
Matrix HTTP Client - Device Mixin
Provides device management methods
"""

from typing import Any


class DeviceMixin:
    """Device management methods for Matrix client"""

    async def get_devices(self) -> dict[str, Any]:
        """
        Get the list of devices for the current user

        Returns:
            List of devices with their information
        """
        endpoint = "/_matrix/client/v3/devices"
        return await self._request("GET", endpoint)

    async def get_device(self, device_id: str) -> dict[str, Any]:
        """
        Get information about a specific device

        Args:
            device_id: The device ID to query

        Returns:
            Device information
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"
        return await self._request("GET", endpoint)

    async def update_device(
        self, device_id: str, display_name: str | None = None
    ) -> dict[str, Any]:
        """
        Update device information

        Args:
            device_id: The device ID to update
            display_name: New display name for the device

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"

        data = {}
        if display_name is not None:
            data["display_name"] = display_name

        return await self._request("PUT", endpoint, data=data)

    async def delete_device(
        self, device_id: str, auth: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Delete a device

        Args:
            device_id: The device ID to delete
            auth: Authentication data (if required)

        Returns:
            Empty dict on success or auth flow information
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"

        data = {}
        if auth:
            data["auth"] = auth

        return await self._request("DELETE", endpoint, data=data)

    async def delete_devices(
        self, device_ids: list[str], auth: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Delete multiple devices

        Args:
            device_ids: List of device IDs
            auth: Authentication data (if required)

        Returns:
            Empty dict on success or auth flow information
        """
        endpoint = "/_matrix/client/v3/delete_devices"
        data: dict[str, Any] = {"devices": device_ids}
        if auth:
            data["auth"] = auth
        return await self._request("POST", endpoint, data=data)
