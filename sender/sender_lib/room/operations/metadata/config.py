"""Room state-event configuration delegation operations."""


class SenderRoomConfigMixin:
    """Delegate room state-event configuration to the client."""

    async def set_room_name(self, room_id: str, name: str) -> dict:
        """Set the Matrix room name."""
        return await self.client.set_room_name(room_id=room_id, name=name)

    async def set_room_topic(
        self,
        room_id: str,
        topic: str,
        formatted_topic: str | None = None,
    ) -> dict:
        """Set a Matrix v1.15 rich room topic with a plain fallback."""
        kwargs = {"room_id": room_id, "topic": topic}
        if formatted_topic is not None:
            kwargs["formatted_topic"] = formatted_topic
        return await self.client.set_room_topic(**kwargs)

    async def set_room_avatar(self, room_id: str, avatar_url: str) -> dict:
        """Set the Matrix room avatar MXC URL."""
        return await self.client.set_room_avatar(
            room_id=room_id,
            avatar_url=avatar_url,
        )

    async def set_room_join_rules(self, room_id: str, join_rule: str) -> dict:
        """Set Matrix room join rules."""
        return await self.client.set_room_join_rules(
            room_id=room_id,
            join_rule=join_rule,
        )

    async def set_room_history_visibility(
        self, room_id: str, history_visibility: str
    ) -> dict:
        """Set Matrix room history visibility."""
        return await self.client.set_room_history_visibility(
            room_id=room_id,
            history_visibility=history_visibility,
        )

    async def set_room_guest_access(self, room_id: str, guest_access: str) -> dict:
        """Set Matrix room guest access."""
        return await self.client.set_room_guest_access(
            room_id=room_id,
            guest_access=guest_access,
        )

    async def set_room_canonical_alias(
        self,
        room_id: str,
        alias: str | None,
        alt_aliases: list[str] | None = None,
    ) -> dict:
        """Set or clear the Matrix room canonical alias."""
        return await self.client.set_room_canonical_alias(
            room_id=room_id,
            alias=alias,
            alt_aliases=alt_aliases,
        )
