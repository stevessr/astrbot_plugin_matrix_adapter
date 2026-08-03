"""Room member storage and profile persistence handlers."""

import asyncio

from astrbot.api import logger

from ....constants import M_ROOM_LIVE_MESSAGING, MSC4357_LIVE_MESSAGING_STATE
from ....storage.stores.rooms import MatrixRoomMemberStore
from ....storage.stores.users import MatrixUserStore


class MatrixEventProcessorMemberStorageMixin:
    """Load room members and persist interacted user profiles."""

    def _init_member_storage(self):
        self.user_store = MatrixUserStore()
        self.room_member_store = MatrixRoomMemberStore()

    async def load_room_members_from_storage(self, room):
        """
        Load room member data from persistent storage.

        Args:
            room: Room object to populate with member data

        Returns:
            True if data was loaded from storage, False otherwise
        """
        room_data = await asyncio.to_thread(self.room_member_store.get, room.room_id)
        if not room_data:
            return False

        room.members = room_data.get("members", {})
        room.member_avatars = room_data.get("member_avatars", {})
        room.member_count = room_data.get("member_count", 0)
        if "is_direct" in room_data:
            room.is_direct = self._parse_bool_like(room_data.get("is_direct"), False)
        if "room_name" in room_data:
            room.display_name = room_data.get("room_name", "")
        if "topic" in room_data:
            room.topic = room_data.get("topic", "")
        if "avatar_url" in room_data:
            room.avatar_url = room_data.get("avatar_url")
        if "join_rules" in room_data:
            room.join_rules = room_data.get("join_rules")
        if "power_levels" in room_data:
            room.power_levels = room_data.get("power_levels")
        if "history_visibility" in room_data:
            room.history_visibility = room_data.get("history_visibility")
        if "guest_access" in room_data:
            room.guest_access = room_data.get("guest_access")
        if "canonical_alias" in room_data:
            room.canonical_alias = room_data.get("canonical_alias")
        if "room_aliases" in room_data:
            room.room_aliases = room_data.get("room_aliases", [])
        if "encryption" in room_data:
            room.encryption = room_data.get("encryption")
        if "create" in room_data:
            room.create = room_data.get("create")
        if "tombstone" in room_data:
            room.tombstone = room_data.get("tombstone")
        if "pinned_events" in room_data:
            room.pinned_events = room_data.get("pinned_events", [])
        if "space_children" in room_data:
            room.space_children = room_data.get("space_children", {})
        if "space_parents" in room_data:
            room.space_parents = room_data.get("space_parents", {})
        if "third_party_invites" in room_data:
            room.third_party_invites = room_data.get("third_party_invites", {})
        if "state_events" in room_data:
            room.state_events = room_data.get("state_events", {})
            for event_type in (
                M_ROOM_LIVE_MESSAGING,
                MSC4357_LIVE_MESSAGING_STATE,
            ):
                live_state = room.state_events.get(event_type, {}).get("", {})
                if not isinstance(live_state, dict):
                    continue
                enabled = live_state.get("enabled")
                if isinstance(enabled, bool):
                    room.live_messaging_enabled = enabled
                else:
                    room.live_messaging_enabled = None
                break

        logger.debug(
            f"从存储加载房间 {room.room_id} 成员数据：{room.member_count} 个成员"
        )
        return True

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
        await asyncio.to_thread(
            self.user_store.upsert, user_id, display_name, avatar_url
        )
