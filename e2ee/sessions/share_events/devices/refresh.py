"""Refresh cached device keys and detect destructive changes."""

from astrbot.api import logger

from .....constants import PREFIX_CURVE25519, PREFIX_ED25519


class E2EEManagerSessionShareEventsDevicesRefreshMixin:
    """查询设备列表并更新设备密钥缓存。"""

    async def _refresh_changed_device_keys(
        self,
        changed_set: set[str],
    ) -> dict[str, bool]:
        # user -> whether a previously known device disappeared or changed
        destructive_changes: dict[str, bool] = {}
        try:
            response = await self.client.query_keys(
                {user_id: [] for user_id in changed_set}
            )
        except Exception as e:
            logger.warning(f"Failed to refresh changed device list: {e}")
            return {}
        response_devices = response.get("device_keys", {})
        if not isinstance(response_devices, dict):
            return {}

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

        return destructive_changes
