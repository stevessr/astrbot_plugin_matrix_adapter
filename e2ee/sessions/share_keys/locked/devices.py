"""Room-key recipient device collection and verification."""

from astrbot.api import logger

from .....constants import PREFIX_CURVE25519, PREFIX_ED25519


class E2EEManagerSessionShareKeysDeviceMixin:
    """Collect verified recipient devices for room-key distribution."""

    async def _collect_room_key_devices(
        self,
        *,
        room_id: str,
        members: list[str],
        shared_devices: set,
    ) -> list[tuple[str, str, str, str]] | None:
        """Return (user_id, device_id, curve_key, ed25519_key) recipients.

        Returns None when the device-key response is malformed.
        """
        response = await self.client.query_keys({user_id: [] for user_id in members})
        device_keys = response.get("device_keys", {})
        if not isinstance(device_keys, dict):
            return None

        member_set = set(members)
        devices_to_send: list[tuple[str, str, str, str]] = []
        for user_id, user_devices in device_keys.items():
            if user_id not in member_set or not isinstance(user_devices, dict):
                continue
            for device_id, device_info in user_devices.items():
                if user_id == self.user_id and device_id == self.device_id:
                    continue
                if not self._olm.verify_device_keys(
                    user_id,
                    device_id,
                    device_info,
                ):
                    logger.warning(
                        "Ignoring device with invalid Matrix self-signature: "
                        f"{user_id}/{device_id}"
                    )
                    continue

                keys = device_info.get("keys", {})
                curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                ed_key = keys.get(f"{PREFIX_ED25519}{device_id}")
                if not isinstance(curve_key, str) or not isinstance(ed_key, str):
                    continue
                if self._store:
                    self._store.save_device_keys(user_id, device_id, device_info)

                cache_key = self._device_cache_key(user_id, device_id, curve_key)
                if cache_key not in shared_devices:
                    devices_to_send.append((user_id, device_id, curve_key, ed_key))

        return devices_to_send
