"""Matrix room membership change handling."""

import asyncio

from astrbot.api import logger

from ....constants import (
    MEMBERSHIP_BAN,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    MEMBERSHIP_KNOCK,
    MEMBERSHIP_LEAVE,
)


class MatrixEventProcessorMembershipChangesMixin:
    """Handle membership changes and update room/profile storage."""

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
        rotated_for_limited_gap = False
        if (
            e2ee_manager
            and getattr(room, "timeline_limited", False)
            and membership != MEMBERSHIP_JOIN
            and user_id != self.user_id
        ):
            # A non-join membership event after a limited timeline may hide an
            # intervening join/leave. Matrix v1.19 requires session rotation.
            try:
                await e2ee_manager.on_room_member_left(room.room_id, user_id)
                rotated_for_limited_gap = True
            except Exception as e:
                logger.debug(f"Limited-sync Megolm rotation failed: {e}")

        if membership == MEMBERSHIP_JOIN:
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
        elif membership == MEMBERSHIP_INVITE:
            if display_name or avatar_url:
                user_store = getattr(self, "user_store", None)
                if user_store is not None:
                    await asyncio.to_thread(
                        user_store.upsert,
                        user_id,
                        display_name,
                        avatar_url,
                    )
            if e2ee_manager and user_id != self.user_id:
                try:
                    on_member_invited = getattr(
                        e2ee_manager,
                        "on_room_member_invited",
                        None,
                    )
                    if callable(on_member_invited):
                        await on_member_invited(room.room_id, user_id)
                except Exception as e:
                    logger.debug(f"Post-invite room-key sharing failed: {e}")
        elif membership == MEMBERSHIP_KNOCK:
            # MSC2403: a user is requesting to join the room.
            # Update profile info and persist; the knock system message
            # is rendered by the receiver's room_state handler.
            if display_name or avatar_url:
                room.members[user_id] = display_name
                if avatar_url:
                    room.member_avatars[user_id] = avatar_url
                user_store = getattr(self, "user_store", None)
                if user_store is not None:
                    await asyncio.to_thread(
                        user_store.upsert, user_id, display_name, avatar_url
                    )
            logger.info(f"用户 {user_id} ({display_name}) 敲门房间 {room.room_id}")
        elif membership in (MEMBERSHIP_LEAVE, MEMBERSHIP_BAN):
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
            if e2ee_manager and not rotated_for_limited_gap:
                try:
                    e2ee_manager.invalidate_room_members_cache(room.room_id)
                    if user_id != self.user_id:
                        on_member_left = getattr(
                            e2ee_manager,
                            "on_room_member_left",
                            None,
                        )
                        if callable(on_member_left):
                            await on_member_left(room.room_id, user_id)
                except Exception as e:
                    logger.debug(f"成员离开后轮换加密会话失败：{e}")
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
