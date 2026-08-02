"""Matrix room key backup version operations."""

from typing import Any

from ..path_utils import quote_path_segment


class KeyBackupVersionsMixin:
    async def get_key_backup_versions(self) -> dict[str, Any]:
        """
        Get current room key backup version

        Returns:
            Version response
        """
        return await self._request("GET", "/_matrix/client/v3/room_keys/version")

    async def get_key_backup_version(self, version: str) -> dict[str, Any]:
        """
        Get a specific backup version

        Args:
            version: Backup version

        Returns:
            Version data
        """
        backup_version = quote_path_segment(version)
        endpoint = f"/_matrix/client/v3/room_keys/version/{backup_version}"
        return await self._request("GET", endpoint)

    async def create_key_backup_version(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new key backup version

        Args:
            data: Backup creation payload

        Returns:
            Response with version
        """
        return await self._request(
            "POST", "/_matrix/client/v3/room_keys/version", data=data
        )

    async def update_key_backup_version(
        self, version: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Update an existing key backup version

        Args:
            version: Backup version
            data: Update payload

        Returns:
            Response data
        """
        backup_version = quote_path_segment(version)
        endpoint = f"/_matrix/client/v3/room_keys/version/{backup_version}"
        return await self._request("PUT", endpoint, data=data)

    async def delete_key_backup_version(self, version: str) -> dict[str, Any]:
        """
        Delete a key backup version

        Args:
            version: Backup version

        Returns:
            Empty dict on success
        """
        backup_version = quote_path_segment(version)
        endpoint = f"/_matrix/client/v3/room_keys/version/{backup_version}"
        return await self._request("DELETE", endpoint)
