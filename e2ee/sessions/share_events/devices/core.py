"""Device-list change hooks for room-key sharing."""


class E2EEManagerSessionShareEventsDevicesCoreMixin:
    """处理设备列表增删与房间密钥缓存更新。"""

    async def on_device_list_changed(self, changed_users: list[str]) -> None:
        """Re-check key sharing when users publish device-list changes.

        Devices that disappeared or changed their identity keys force a
        Megolm session rotation; newly added devices receive the current
        session key.
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

        destructive_changes = await self._refresh_changed_device_keys(changed_set)
        if not destructive_changes:
            return

        await self._recheck_room_key_sharing(
            room_ids,
            changed_set,
            destructive_changes,
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
