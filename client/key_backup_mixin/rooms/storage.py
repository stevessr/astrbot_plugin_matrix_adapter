"""Store room key backup keys."""

from typing import Any

from ...path_utils import quote_path_segment


class KeyBackupRoomKeysStorageMixin:
    """Store key backup keys for rooms and sessions."""

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
