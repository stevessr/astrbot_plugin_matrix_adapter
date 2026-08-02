"""Signed device-key object verification."""


class OlmMachineKeyDeviceVerificationMixin:
    @classmethod
    def verify_device_keys(
        cls,
        user_id: str,
        device_id: str,
        device_info: dict,
    ) -> bool:
        """Validate a device-keys object and its mandatory self-signature."""
        if not isinstance(device_info, dict):
            return False
        if device_info.get("user_id") != user_id:
            return False
        if device_info.get("device_id") != device_id:
            return False
        algorithms = device_info.get("algorithms")
        if not isinstance(algorithms, list) or not all(
            isinstance(algorithm, str) and algorithm for algorithm in algorithms
        ):
            return False
        keys = device_info.get("keys")
        if not isinstance(keys, dict):
            return False
        ed25519_key_id = f"ed25519:{device_id}"
        ed25519_key = keys.get(ed25519_key_id)
        curve25519_key = keys.get(f"curve25519:{device_id}")
        if not isinstance(ed25519_key, str) or not ed25519_key:
            return False
        if not isinstance(curve25519_key, str) or not curve25519_key:
            return False
        return cls.verify_json_signature(
            device_info,
            user_id,
            ed25519_key_id,
            ed25519_key,
        )
