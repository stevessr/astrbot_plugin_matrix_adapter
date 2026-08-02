"""Matrix direct-message and marked-unread room operations."""

from typing import Any

from astrbot.api import logger

from ....constants import M_MARKED_UNREAD, MSC2867_MARKED_UNREAD


class ProfileRoomStateMixin:
    async def get_user_room(self, user_id: str) -> str | None:
        """
        Find a direct message room with the specified user

        Args:
            user_id: The user ID to find a DM room for

        Returns:
            The room ID if found, None otherwise
        """
        try:
            # Get direct chat map from account data
            account_data = await self.get_global_account_data("m.direct")
            content = account_data.get("content", {})

            # Look for rooms with this user
            rooms = content.get(user_id, [])
            if isinstance(rooms, list):
                for room_id in rooms:
                    room_id_text = str(room_id or "").strip()
                    if room_id_text:
                        return room_id_text

            return None
        except Exception as e:
            logger.warning(f"Failed to find DM room for {user_id}: {e}")
            return None

    async def set_room_marked_unread(
        self, room_id: str, unread: bool = True
    ) -> dict[str, Any]:
        """
        Mark a room as (un)read on the user's account (MSC2867).

        Writes both the stable ``m.marked_unread`` key (Matrix v1.12+) and the
        legacy ``com.famedly.marked_unread`` key for older clients/servers.
        """
        content = {"unread": bool(unread)}
        # Stable key (room account data)
        await self.set_room_account_data(room_id, M_MARKED_UNREAD, content)
        # Legacy unstable key for older clients
        try:
            await self.set_room_account_data(room_id, MSC2867_MARKED_UNREAD, content)
        except Exception as e:
            logger.debug(f"Failed to set legacy marked_unread: {e}")
        return content

    async def get_room_marked_unread(self, room_id: str) -> bool:
        """Read the marked-unread state of a room (MSC2867)."""
        for type_key in (M_MARKED_UNREAD, MSC2867_MARKED_UNREAD):
            try:
                data = await self.get_room_account_data(room_id, type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and "unread" in content:
                return bool(content.get("unread"))
            if isinstance(data, dict) and "unread" in data:
                return bool(data.get("unread"))
        return False
