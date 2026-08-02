"""Signed one-time and fallback key selection."""


class OlmMachineKeyOneTimeVerificationMixin:
    @classmethod
    def select_verified_one_time_key(
        cls,
        user_id: str,
        device_id: str,
        device_ed25519_key: str,
        device_one_time_keys: dict,
    ) -> tuple[str, str] | None:
        """Return the first valid signed_curve25519 one-time/fallback key.

        Claimed keys are controlled by the homeserver until their device
        signature is verified.  Never fall back to accepting a raw or invalid
        key: doing so would allow a malicious server to establish its own Olm
        session in place of the target device.
        """
        if not isinstance(device_one_time_keys, dict):
            return None
        signing_key_id = f"ed25519:{device_id}"
        for key_id, key_data in device_one_time_keys.items():
            if not isinstance(key_id, str) or not key_id.startswith(
                "signed_curve25519:"
            ):
                continue
            if not isinstance(key_data, dict):
                continue
            curve_key = key_data.get("key")
            if not isinstance(curve_key, str) or not curve_key:
                continue
            if cls.verify_json_signature(
                key_data,
                user_id,
                signing_key_id,
                device_ed25519_key,
            ):
                return key_id, curve_key
        return None
