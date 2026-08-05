"""General room creation."""

from typing import Any


class UserRoomCreationGeneralMixin:
    """Create general Matrix rooms."""

    async def create_room(
        self,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new room

        Args:
            name: Room name
            topic: Room topic
            invite: List of user IDs to invite
            is_public: Whether room is public
            preset: Room preset (private_chat, public_chat, trusted_private_chat)
            creation_content: Room creation_content payload
            initial_state: Room initial_state payload

        Returns:
            Response with room_id
        """
        data = self._build_create_room_data(
            name,
            topic,
            invite,
            is_public,
            preset,
            creation_content,
            initial_state,
        )

        endpoint = "/_matrix/client/v3/createRoom"
        return await self._request("POST", endpoint, data=data)

    def _build_create_room_data(
        self,
        name: str | None,
        topic: str | None,
        invite: list[str] | None,
        is_public: bool,
        preset: str | None,
        creation_content: dict[str, Any] | None,
        initial_state: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}

        if name:
            data["name"] = name
        if topic:
            data["topic"] = topic
        if invite:
            data["invite"] = invite
        if preset:
            data["preset"] = preset
        else:
            data["preset"] = "public_chat" if is_public else "private_chat"

        if is_public:
            data["visibility"] = "public"

        if creation_content and isinstance(creation_content, dict):
            data["creation_content"] = creation_content

        if initial_state and isinstance(initial_state, list):
            data["initial_state"] = initial_state

        return data


__all__ = ["UserRoomCreationGeneralMixin"]
