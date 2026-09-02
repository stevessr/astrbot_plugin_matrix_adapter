"""Room forgetting and upgrade operations."""

from typing import Any

from ...path_utils import quote_path_segment


class RoomTransitionMixin:
    """Manage room lifecycle transitions."""

    async def forget_room(self, room_id: str) -> dict[str, Any]:
        """
        Forget a room (after leaving)

        Args:
            room_id: Room ID

        Returns:
            Empty dict on success
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/forget"
        return await self._request("POST", endpoint, data={})

    async def upgrade_room(
        self,
        room_id: str,
        new_version: str,
        additional_creators: list[str] | None = None,
    ) -> dict[str, Any]:
        """Upgrade a room to a new version.

        Matrix v1.16 / room version 12 allows the complete set of additional
        room creators to be supplied explicitly. Existing additional creators
        are not copied by the homeserver unless the client sends them again.
        """
        room = quote_path_segment(room_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/upgrade"
        data: dict[str, Any] = {"new_version": new_version}
        if additional_creators is not None:
            if not isinstance(additional_creators, list) or not all(
                isinstance(user_id, str) and user_id.startswith("@")
                for user_id in additional_creators
            ):
                raise ValueError("additional_creators must be a list of Matrix user IDs")
            data["additional_creators"] = list(dict.fromkeys(additional_creators))
        return await self._request("POST", endpoint, data=data)


__all__ = ["RoomTransitionMixin"]
