"""
Matrix Event Processor - member/profile handlers.
"""

import asyncio

from astrbot.api import logger

from ..room_member_store import MatrixRoomMemberStore
from ..user_store import MatrixUserStore


class MatrixEventProcessorMembers:
    """Mixin for membership updates and profile persistence."""

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
            room.is_direct = room_data.get("is_direct")
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
        await asyncio.to_thread(self.user_store.upsert, user_id, display_name, avatar_url)

    async def _handle_member_event(self, room, event_data: dict):
        """Handle m.room.member changes and persist profile updates."""
        user_id = event_data.get("state_key")
        if not user_id:
            return
        e2ee_manager = getattr(self, "e2ee_manager", None)
        content = event_data.get("content", {})
        membership = content.get("membership")
        display_name = content.get("displayname") or room.members.get(user_id, user_id)
        avatar_url = content.get("avatar_url") or room.member_avatars.get(user_id)

        if membership == "join":
            is_new_member = user_id not in room.members
            room.members[user_id] = display_name
            if avatar_url:
                room.member_avatars[user_id] = avatar_url
            await asyncio.to_thread(
                self.user_store.upsert, user_id, display_name, avatar_url
            )
            if is_new_member:
                room.member_count += 1
                logger.info(
                    f"用户 {user_id} ({display_name}) 加入房间 {room.room_id}，"
                    f"当前人数：{room.member_count}"
                )
                # Update room member storage
                await asyncio.to_thread(
                    self.room_member_store.upsert,
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                    room_name=room.display_name,
                    topic=room.topic,
                    avatar_url=room.avatar_url,
                    join_rules=room.join_rules,
                    power_levels=room.power_levels,
                    history_visibility=room.history_visibility,
                    guest_access=room.guest_access,
                    canonical_alias=room.canonical_alias,
                    room_aliases=room.room_aliases,
                    encryption=room.encryption,
                    create=room.create,
                    tombstone=room.tombstone,
                    pinned_events=room.pinned_events,
                    space_children=room.space_children,
                    space_parents=room.space_parents,
                    third_party_invites=room.third_party_invites,
                    state_events=room.state_events,
                )
                if e2ee_manager:
                    try:
                        e2ee_manager.invalidate_room_members_cache(room.room_id)
                        if user_id != self.user_id:
                            await e2ee_manager.on_room_member_joined(
                                room.room_id, user_id
                            )
                    except Exception as e:
                        logger.debug(f"成员加入后的主动密钥分发失败：{e}")
        elif membership in ("leave", "ban"):
            was_member = user_id in room.members
            room.members.pop(user_id, None)
            room.member_avatars.pop(user_id, None)
            if was_member and room.member_count > 0:
                room.member_count -= 1
                logger.info(
                    f"用户 {user_id} ({display_name}) 离开房间 {room.room_id}，"
                    f"当前人数：{room.member_count}"
                )
                # Update room member storage
                await asyncio.to_thread(
                    self.room_member_store.upsert,
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                    room_name=room.display_name,
                    topic=room.topic,
                    avatar_url=room.avatar_url,
                    join_rules=room.join_rules,
                    power_levels=room.power_levels,
                    history_visibility=room.history_visibility,
                    guest_access=room.guest_access,
                    canonical_alias=room.canonical_alias,
                    room_aliases=room.room_aliases,
                    encryption=room.encryption,
                    create=room.create,
                    tombstone=room.tombstone,
                    pinned_events=room.pinned_events,
                    space_children=room.space_children,
                    space_parents=room.space_parents,
                    third_party_invites=room.third_party_invites,
                    state_events=room.state_events,
                )
                if e2ee_manager:
                    try:
                        e2ee_manager.invalidate_room_members_cache(room.room_id)
                    except Exception as e:
                        logger.debug(f"成员离开后刷新成员缓存失败：{e}")
        else:
            # Membership changes without join/leave still update profile fields if present.
            if content.get("displayname") or content.get("avatar_url"):
                room.members[user_id] = display_name
                if avatar_url:
                    room.member_avatars[user_id] = avatar_url
                await asyncio.to_thread(
                    self.user_store.upsert, user_id, display_name, avatar_url
                )
                # Update room member storage
                await asyncio.to_thread(
                    self.room_member_store.upsert,
                    room_id=room.room_id,
                    members=room.members,
                    member_avatars=room.member_avatars,
                    member_count=room.member_count,
                    is_direct=room.is_direct,
                    room_name=room.display_name,
                    topic=room.topic,
                    avatar_url=room.avatar_url,
                    join_rules=room.join_rules,
                    power_levels=room.power_levels,
                    history_visibility=room.history_visibility,
                    guest_access=room.guest_access,
                    canonical_alias=room.canonical_alias,
                    room_aliases=room.room_aliases,
                    encryption=room.encryption,
                    create=room.create,
                    tombstone=room.tombstone,
                    pinned_events=room.pinned_events,
                    space_children=room.space_children,
                    space_parents=room.space_parents,
                    third_party_invites=room.third_party_invites,
                    state_events=room.state_events,
                )
