"""Sender-key resolution from the local device cache."""


class E2EEManagerDecryptDeviceLocalMixin:
    """Find a validated device in the local key cache."""

    def _find_sender_device_in_local_cache(
        self,
        sender_key: str,
        sender_user_id: str | None,
    ) -> tuple[str, str] | None:
        """Return ``(user_id, device_id)`` when cached, else ``None``."""
        if self._store:
            device_keys = self._store.get_all_device_keys()
            for user_id, devices in device_keys.items():
                for device_id, keys in devices.items():
                    if sender_user_id and user_id != sender_user_id:
                        continue
                    if not self._olm.verify_device_keys(user_id, device_id, keys):
                        continue
                    device_curve_key = keys.get("keys", {}).get(
                        f"curve25519:{device_id}"
                    )
                    if device_curve_key == sender_key:
                        return (user_id, device_id)
        return None


__all__ = ["E2EEManagerDecryptDeviceLocalMixin"]
