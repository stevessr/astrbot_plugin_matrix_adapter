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
        room_version: str | None = None,
        additional_creators: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new room, including room-v12 creator metadata when needed."""
        data = self._build_create_room_data(
            name,
            topic,
            invite,
            is_public,
            preset,
            creation_content,
            initial_state,
            room_version,
            additional_creators,
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
        room_version: str | None = None,
        additional_creators: list[str] | None = None,
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
        if room_version:
            data["room_version"] = str(room_version)

        create_content = (
            dict(creation_content)
            if isinstance(creation_content, dict)
            else {}
        )
        if additional_creators is not None:
            if not isinstance(additional_creators, list) or not all(
                isinstance(user_id, str) and user_id.startswith("@")
                for user_id in additional_creators
            ):
                raise ValueError("additional_creators must be a list of Matrix user IDs")
            create_content["additional_creators"] = list(
                dict.fromkeys(additional_creators)
            )
        if create_content:
            data["creation_content"] = create_content

        if initial_state and isinstance(initial_state, list):
            data["initial_state"] = initial_state

        return data


__all__ = ["UserRoomCreationGeneralMixin"]
