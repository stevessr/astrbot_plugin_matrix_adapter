"""Device-list change hooks for room-key sharing."""

from astrbot.api import logger

from ....constants import PREFIX_CURVE25519, PREFIX_ED25519


class E2EEManagerSessionShareEventsDevicesMixin:
    """处理设备列表增删与房间密钥缓存更新。"""

    async def on_device_list_changed(self, changed_users: list[str]) -> None:
        """Re-check key sharing when users publish device-list changes.

        This event-driven path remains active in lazy mode so newly announced
        devices can receive an existing outbound room key without a periodic scan.

        Args:
            changed_users: Matrix users whose device lists changed.
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        changed_set = {
            user_id for user_id in changed_users if user_id and isinstance(user_id, str)
        }
        if not changed_set:
            return

        room_ids = self._olm.get_megolm_outbound_room_ids()
        if not room_ids:
            return

        try:
            response = await self.client.query_keys(
                {user_id: [] for user_id in changed_set}
            )
        except Exception as e:
            logger.warning(f"Failed to refresh changed device list: {e}")
            return
        response_devices = response.get("device_keys", {})
        if not isinstance(response_devices, dict):
            return

        # user -> whether a previously known device disappeared or changed
        destructive_changes: dict[str, bool] = {}
        for user_id in changed_set:
            if user_id not in response_devices:
                # A partial/federation failure must not be interpreted as all
                # devices being deleted.
                continue
            raw_current = response_devices.get(user_id)
            if not isinstance(raw_current, dict):
                continue
            current = {
                device_id: device_info
                for device_id, device_info in raw_current.items()
                if isinstance(device_id, str)
                and self._olm.verify_device_keys(user_id, device_id, device_info)
            }
            previous = {}
            if self._store:
                all_keys = self._store.get_all_device_keys()
                previous = (
                    all_keys.get(user_id) or {} if isinstance(all_keys, dict) else {}
                )

            def identity_map(devices: object) -> dict[str, tuple[str, str]]:
                if not isinstance(devices, dict):
                    return {}
                identities: dict[str, tuple[str, str]] = {}
                for device_id, device_info in devices.items():
                    if not isinstance(device_info, dict):
                        continue
                    keys = device_info.get("keys") or {}
                    curve = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    ed = keys.get(f"{PREFIX_ED25519}{device_id}")
                    if isinstance(curve, str) and isinstance(ed, str):
                        identities[str(device_id)] = (curve, ed)
                return identities

            old_identities = identity_map(previous)
            new_identities = identity_map(current)
            destructive_changes[user_id] = any(
                new_identities.get(device_id) != identity
                for device_id, identity in old_identities.items()
            )
            if self._store:
                replace = getattr(self._store, "replace_user_device_keys", None)
                if callable(replace):
                    replace(user_id, current)
                else:
                    for device_id, device_info in current.items():
                        self._store.save_device_keys(user_id, device_id, device_info)

        if not destructive_changes:
            return

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

    async def on_device_list_left(self, left_users: list[str]) -> None:
        """Forget users for whom /sync says no encrypted rooms are shared."""
        left = {user_id for user_id in left_users if isinstance(user_id, str)}
        if not left:
            return
        if self._store:
            delete = getattr(self._store, "delete_user_device_keys", None)
            if callable(delete):
                for user_id in left:
                    delete(user_id)
        share_cache = getattr(self, "_room_key_share_cache", {})
        for shared_devices in share_cache.values():
            shared_devices.difference_update(
                cache_key
                for cache_key in tuple(shared_devices)
                if cache_key.split("|", 1)[0] in left
            )
