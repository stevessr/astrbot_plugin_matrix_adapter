"""Matrix device lookup operations."""

from typing import Any

from ..path_utils import quote_path_segment


class DeviceListingMixin:
    """List devices and inspect an individual device."""

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
        device = quote_path_segment(device_id)
        endpoint = f"/_matrix/client/v3/devices/{device}"
        return await self._request("GET", endpoint)
