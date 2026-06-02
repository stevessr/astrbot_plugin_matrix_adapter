"""
Matrix HTTP Client - Key Backup Mixin
Provides room key backup API methods
"""

from typing import Any

from .path_utils import quote_path_segment


class KeyBackupMixin:
    """Room key backup methods for Matrix client"""

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

    async def get_room_keys(self, version: str) -> dict[str, Any]:
        """
        Get all room keys for a backup version

        Args:
            version: Backup version

        Returns:
            Room keys response
        """
        return await self._request(
            "GET",
            "/_matrix/client/v3/room_keys/keys",
            params={"version": version},
        )

    async def get_room_keys_for_room(
        self, version: str, room_id: str
    ) -> dict[str, Any]:
        """
        Get all room keys for a specific room

        Args:
            version: Backup version
            room_id: Room ID

        Returns:
            Room keys response
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/room_keys/keys/{room}"
        return await self._request("GET", endpoint, params={"version": version})

    async def get_room_key_for_session(
        self, version: str, room_id: str, session_id: str
    ) -> dict[str, Any]:
        """
        Get a specific room key session

        Args:
            version: Backup version
            room_id: Room ID
            session_id: Session ID

        Returns:
            Session data
        """
        room = quote_path_segment(room_id)
        session = quote_path_segment(session_id)
        endpoint = f"/_matrix/client/v3/room_keys/keys/{room}/{session}"
        return await self._request("GET", endpoint, params={"version": version})

    async def store_room_keys(
        self, version: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Store room keys for a backup version

        Args:
            version: Backup version
            data: Room keys payload

        Returns:
            Empty dict on success
        """
        return await self._request(
            "PUT",
            "/_matrix/client/v3/room_keys/keys",
            data=data,
            params={"version": version},
        )

    async def store_room_key_for_session(
        self, version: str, room_id: str, session_id: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Store a single room key session for a backup version.

        Args:
            version: Backup version
            room_id: Room ID
            session_id: Megolm session ID
            data: Session payload

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        session = quote_path_segment(session_id)
        endpoint = f"/_matrix/client/v3/room_keys/keys/{room}/{session}"
        return await self._request(
            "PUT", endpoint, data=data, params={"version": version}
        )

    async def delete_room_keys(self, version: str) -> dict[str, Any]:
        """
        Delete all room keys for a backup version

        Args:
            version: Backup version

        Returns:
            Empty dict on success
        """
        return await self._request(
            "DELETE",
            "/_matrix/client/v3/room_keys/keys",
            params={"version": version},
        )

    async def delete_room_keys_for_room(
        self, version: str, room_id: str
    ) -> dict[str, Any]:
        """
        Delete room keys for a specific room

        Args:
            version: Backup version
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/room_keys/keys/{room}"
        return await self._request("DELETE", endpoint, params={"version": version})

    async def delete_room_key_for_session(
        self, version: str, room_id: str, session_id: str
    ) -> dict[str, Any]:
        """
        Delete a specific room key session

        Args:
            version: Backup version
            room_id: Room ID
            session_id: Session ID

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        session = quote_path_segment(session_id)
        endpoint = f"/_matrix/client/v3/room_keys/keys/{room}/{session}"
        return await self._request("DELETE", endpoint, params={"version": version})
