"""Room configuration, directory, pins, and unread metadata operations."""

from typing import Any


class SenderRoomMetadataMixin:
    """Delegates room configuration and metadata operations."""

    async def set_room_name(self, room_id: str, name: str) -> dict:
        """Set the Matrix room name."""
        return await self.client.set_room_name(room_id=room_id, name=name)

    async def set_room_topic(self, room_id: str, topic: str) -> dict:
        """Set the Matrix room topic."""
        return await self.client.set_room_topic(room_id=room_id, topic=topic)

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

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict:
        """Create or update a Matrix room alias."""
        return await self.client.create_room_alias(
            room_alias=room_alias,
            room_id=room_id,
        )

    async def delete_room_alias(self, room_alias: str) -> dict:
        """Delete a Matrix room alias."""
        return await self.client.delete_room_alias(room_alias)

    async def get_room_alias(self, room_alias: str) -> dict:
        """Resolve a Matrix room alias to its room ID and servers."""
        return await self.client.get_room_alias(room_alias)

    async def list_public_rooms(
        self,
        *,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict:
        """List Matrix public rooms, optionally on another server."""
        return await self.client.list_public_rooms(
            server=server,
            limit=limit,
            since=since,
            filter=filter,
        )

    async def get_room_visibility(self, room_id: str) -> dict:
        """Get room visibility in the public directory."""
        return await self.client.get_room_visibility(room_id)

    async def set_room_visibility(self, room_id: str, visibility: str) -> dict:
        """Set room visibility in the public directory."""
        return await self.client.set_room_visibility(
            room_id=room_id,
            visibility=visibility,
        )

    async def get_room_aliases(self, room_id: str) -> dict:
        """Get aliases associated with a Matrix room."""
        return await self.client.get_room_aliases(room_id)

    async def get_pinned_messages(self, room_id: str) -> list[str]:
        """Get pinned Matrix event IDs in a room."""
        return await self.client.get_room_pinned_events(room_id)

    async def set_pinned_messages(self, room_id: str, event_ids) -> dict:
        """Replace pinned Matrix event IDs in a room."""
        return await self.client.set_room_pinned_events(room_id, event_ids)

    async def pin_message(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict:
        """Pin a Matrix event in a room."""
        return await self.client.pin_room_event(
            room_id=room_id,
            event_id=event_id,
            prepend=prepend,
        )

    async def unpin_message(self, room_id: str, event_id: str) -> dict:
        """Unpin a Matrix event in a room."""
        return await self.client.unpin_room_event(room_id=room_id, event_id=event_id)

    async def mark_room_unread(self, room_id: str, unread: bool = True) -> dict:
        """Mark a room as (un)read for this account (MSC2867)."""
        return await self.client.set_room_marked_unread(room_id, unread)
