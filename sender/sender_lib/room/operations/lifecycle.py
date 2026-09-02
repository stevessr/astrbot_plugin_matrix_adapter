"""Room creation, membership lifecycle, summary, and knock operations."""

from typing import Any


class SenderRoomLifecycleMixin:
    """Delegates room creation, membership lifecycle, summary, and knock operations."""

    async def create_room(
        self,
        *,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
        room_version: str | None = None,
        additional_creators: list[str] | None = None,
    ) -> dict:
        """Create a Matrix room, optionally with room-v12 creator metadata."""
        kwargs: dict[str, Any] = {
            "name": name,
            "topic": topic,
            "invite": invite,
            "is_public": is_public,
            "preset": preset,
            "creation_content": creation_content,
            "initial_state": initial_state,
        }
        if room_version is not None:
            kwargs["room_version"] = room_version
        if additional_creators is not None:
            kwargs["additional_creators"] = additional_creators
        return await self.client.create_room(**kwargs)

    async def create_dm_room(self, user_id: str, name: str | None = None) -> dict:
        """Create a Matrix direct-message room and update m.direct when possible."""
        return await self.client.create_dm_room(user_id=user_id, name=name)

    async def get_user_room(self, user_id: str) -> str | None:
        """Find an existing direct-message room for a Matrix user."""
        return await self.client.get_user_room(user_id)

    async def join_room(
        self,
        room_id_or_alias: str,
        server_name: list[str] | None = None,
        *,
        via: list[str] | None = None,
    ) -> dict:
        """Join a Matrix room through stable ``via`` servers.

        ``server_name`` is retained as a deprecated source-compatible alias.
        Unspecified routing options are not forwarded, preserving compatibility
        with custom client wrappers that predate the stable ``via`` parameter.
        """
        kwargs: dict[str, Any] = {}
        if server_name is not None:
            kwargs["server_name"] = server_name
        if via is not None:
            kwargs["via"] = via
        return await self.client.join_room(room_id_or_alias, **kwargs)

    async def join_room_from_upgrade_reference(
        self,
        room_id: str,
        event_sender: str,
    ) -> dict:
        """Join a room referenced by a tombstone/predecessor event.

        Matrix v1.19 recommends using the reference event sender's homeserver as
        a stable ``via`` server when following upgrade references.
        """
        via_server: str | None = None
        if isinstance(event_sender, str) and event_sender.startswith("@"):
            _, separator, server = event_sender[1:].partition(":")
            if separator and server:
                via_server = server
        return await self.join_room(
            room_id,
            via=[via_server] if via_server else None,
        )

    async def leave_room(self, room_id: str) -> dict:
        """Leave a Matrix room."""
        return await self.client.leave_room(room_id)

    async def forget_room(self, room_id: str) -> dict:
        """Forget a Matrix room after leaving it."""
        return await self.client.forget_room(room_id)

    async def get_joined_rooms(self) -> list[str]:
        """Get room IDs joined by the current Matrix account."""
        return await self.client.get_joined_rooms()

    async def upgrade_room(
        self,
        room_id: str,
        new_version: str,
        additional_creators: list[str] | None = None,
    ) -> dict:
        """Upgrade a room, preserving/supplying room-v12 additional creators."""
        kwargs: dict[str, Any] = {
            "room_id": room_id,
            "new_version": new_version,
        }
        if additional_creators is not None:
            kwargs["additional_creators"] = additional_creators
        return await self.client.upgrade_room(**kwargs)

    async def knock_room(
        self,
        room_id_or_alias: str,
        reason: str | None = None,
        server_name: list[str] | None = None,
        *,
        via: list[str] | None = None,
    ) -> dict:
        """Knock on a Matrix room through stable ``via`` servers."""
        kwargs: dict[str, Any] = {"room_id_or_alias": room_id_or_alias}
        if reason is not None:
            kwargs["reason"] = reason
        if server_name is not None:
            kwargs["server_name"] = server_name
        if via is not None:
            kwargs["via"] = via
        return await self.client.knock_room(**kwargs)

    async def accept_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Accept a Matrix knock request by inviting the user."""
        return await self.client.accept_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def reject_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Reject a Matrix knock request by kicking the knocking user."""
        return await self.client.reject_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def get_room_summary(
        self,
        room_id_or_alias: str,
        *,
        via: list[str] | None = None,
    ) -> dict:
        """Get the Matrix v1.15 stable summary for a room or alias."""
        kwargs: dict[str, Any] = {"room_id_or_alias": room_id_or_alias}
        if via is not None:
            kwargs["via"] = via
        return await self.client.get_room_summary(**kwargs)

    async def get_room_hierarchy(
        self,
        room_id: str,
        *,
        limit: int | None = None,
        from_token: str | None = None,
    ) -> dict:
        """Get Matrix space/room hierarchy."""
        return await self.client.get_room_hierarchy(
            room_id=room_id,
            limit=limit,
            from_token=from_token,
        )
