"""
Matrix Event Processor - member/profile handlers.
"""

from ..user_store import MatrixUserStore


class MatrixEventProcessorMembers:
    """Mixin for membership updates and profile persistence."""

    def _init_member_storage(self):
        self.user_store = MatrixUserStore()

    async def _persist_interacted_user(self, room, event):
        """Persist profile info for interacted users."""
        user_id = getattr(event, "sender", None)
        if not user_id:
            return
        display_name = room.members.get(user_id, user_id)
        avatar_url = room.member_avatars.get(user_id)
        if not avatar_url and self.client:
            try:
                avatar_url = await self.client.get_avatar_url(user_id)
            except Exception:
                avatar_url = None
        self.user_store.upsert(user_id, display_name, avatar_url)

    async def _handle_member_event(self, room, event_data: dict):
        """Handle m.room.member changes and persist profile updates."""
        user_id = event_data.get("state_key")
        if not user_id:
            return
        content = event_data.get("content", {})
        membership = content.get("membership")
        display_name = content.get("displayname") or room.members.get(user_id, user_id)
        avatar_url = content.get("avatar_url") or room.member_avatars.get(user_id)

        if membership == "join":
            room.members[user_id] = display_name
            if avatar_url:
                room.member_avatars[user_id] = avatar_url
            self.user_store.upsert(user_id, display_name, avatar_url)
        elif membership in ("leave", "ban"):
            room.members.pop(user_id, None)
            room.member_avatars.pop(user_id, None)
        else:
            # Membership changes without join/leave still update profile fields if present.
            if content.get("displayname") or content.get("avatar_url"):
                room.members[user_id] = display_name
                if avatar_url:
                    room.member_avatars[user_id] = avatar_url
                self.user_store.upsert(user_id, display_name, avatar_url)
