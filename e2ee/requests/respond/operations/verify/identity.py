"""Requester identity-key loading."""

from ......constants import PREFIX_CURVE25519, PREFIX_ED25519


class E2EEManagerRequestsRespondIdentityMixin:
    """Load and validate a requester's signed identity keys."""

    async def _load_requester_identity(
        self,
        sender: str,
        requesting_device_id: str,
    ):
        """Return ``(device_info, curve_key, ed25519_key, resp)`` or ``None``."""
        resp = await self.client.query_keys({sender: []})
        devices = (resp.get("device_keys") or {}).get(sender) or {}
        device_info = devices.get(requesting_device_id, {})
        curve_key = device_info.get("keys", {}).get(
            f"{PREFIX_CURVE25519}{requesting_device_id}"
        )
        ed25519_key = device_info.get("keys", {}).get(
            f"{PREFIX_ED25519}{requesting_device_id}"
        )

        if (
            not curve_key
            or not ed25519_key
            or not self._olm.verify_device_keys(
                sender,
                requesting_device_id,
                device_info,
            )
        ):
            return None

        return device_info, curve_key, ed25519_key, resp


__all__ = ["E2EEManagerRequestsRespondIdentityMixin"]
