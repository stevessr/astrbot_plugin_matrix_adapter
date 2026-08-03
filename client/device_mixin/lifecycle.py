"""Matrix device update and deletion operations."""

from typing import Any

from ..path_utils import quote_path_segment


class DeviceLifecycleMixin:
    """Update and remove one or more devices."""

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
        device = quote_path_segment(device_id)
        endpoint = f"/_matrix/client/v3/devices/{device}"

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
        device = quote_path_segment(device_id)
        endpoint = f"/_matrix/client/v3/devices/{device}"

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
