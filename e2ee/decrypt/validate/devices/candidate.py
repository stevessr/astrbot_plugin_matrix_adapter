"""Sender-key resolution from a candidate device set."""


class E2EEManagerDecryptDeviceCandidateMixin:
    """Find a validated device matching the given keys."""

    def _find_validated_sender_device(
        self,
        user_id: str,
        curve25519_key: str,
        ed25519_key: str,
        candidates: object,
    ) -> tuple[str, dict] | None:
        if not isinstance(candidates, dict):
            return None
        for device_id, device_info in candidates.items():
            if not isinstance(device_id, str) or not self._olm.verify_device_keys(
                user_id,
                device_id,
                device_info,
            ):
                continue
            keys = device_info.get("keys", {})
            if (
                keys.get(f"curve25519:{device_id}") == curve25519_key
                and keys.get(f"ed25519:{device_id}") == ed25519_key
            ):
                return device_id, device_info
        return None


__all__ = ["E2EEManagerDecryptDeviceCandidateMixin"]
