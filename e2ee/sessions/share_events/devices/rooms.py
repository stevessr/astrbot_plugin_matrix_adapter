"""Re-share or rotate room keys after device-list changes."""

from astrbot.api import logger


class E2EEManagerSessionShareEventsDevicesRoomsMixin:
    """按房间检查受影响成员并分发或轮换密钥。"""

    async def _recheck_room_key_sharing(
        self,
        room_ids: list,
        changed_set: set[str],
        destructive_changes: dict[str, bool],
    ) -> None:
        affected_rooms = 0
        affected_users = 0
        for room_id in room_ids:
            members = await self._get_room_members(room_id)
            if not members:
                continue
            target_users = [user_id for user_id in members if user_id in changed_set]
            if not target_users:
                continue
            if any(destructive_changes.get(user_id) for user_id in target_users):
                # A removed/re-keyed device already has the current Megolm key;
                # rotate before any future message rather than only updating
                # the share cache for newly added devices.
                self._discard_outbound_session(room_id)
                affected_rooms += 1
                affected_users += len(target_users)
                continue
            await self._share_existing_room_key(
                room_id=room_id,
                target_users=target_users,
                reason="device_list_changed",
            )
            affected_rooms += 1
            affected_users += len(target_users)

        if affected_rooms:
            logger.info(
                f"设备列表变更后已主动检查密钥分发：rooms={affected_rooms} users={affected_users}"
            )
