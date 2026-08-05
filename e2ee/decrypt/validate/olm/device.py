"""Olm sender device-key validation."""


class E2EEManagerDecryptOlmDeviceMixin:
    """Validate and store the sender's declared device keys."""

    def _validate_olm_sender_device_keys(
        self,
        event_sender: str,
        sender_curve25519_key: str,
        claimed_ed25519: str,
        sender_device_keys: dict,
    ) -> bool:
        if not isinstance(sender_device_keys, dict):
            return False
        device_id = sender_device_keys.get("device_id")
        if not isinstance(device_id, str) or not device_id:
            return False
        keys = sender_device_keys.get("keys")
        if not isinstance(keys, dict):
            return False
        if sender_device_keys.get("user_id") != event_sender:
            return False
        if keys.get(f"curve25519:{device_id}") != sender_curve25519_key:
            return False
        if keys.get(f"ed25519:{device_id}") != claimed_ed25519:
            return False
        if not self._olm.verify_device_keys(
            event_sender,
            device_id,
            sender_device_keys,
        ):
            return False
        if self._store:
            self._store.save_device_keys(
                event_sender,
                device_id,
                sender_device_keys,
            )
        mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
        if callable(mark_succeeded):
            mark_succeeded(event_sender, device_id)
        return True


__all__ = ["E2EEManagerDecryptOlmDeviceMixin"]
