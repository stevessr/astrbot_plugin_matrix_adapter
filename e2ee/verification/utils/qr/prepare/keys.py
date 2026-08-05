"""Fetch keys needed for a self-verification QR."""

from ......constants import PREFIX_ED25519


class SASVerificationFlowQRPrepareKeysMixin:
    """Query the peer's device and master keys."""

    async def _fetch_self_verification_qr_keys(
        self,
        sender: str,
        peer_device: str | None,
        session: dict,
    ) -> tuple:
        """Return ``(peer_device_key, current_device_key, master_key, response)``."""
        response = await self.client.query_keys({sender: []})
        device_keys = (response.get("device_keys") or {}).get(sender) or {}
        peer_device_info = device_keys.get(peer_device) or {}
        peer_keys = peer_device_info.get("keys") or {}
        peer_device_key = peer_keys.get(f"{PREFIX_ED25519}{peer_device}")
        if peer_device_key:
            session["fingerprint"] = peer_device_key

        master_key_obj = (response.get("master_keys") or {}).get(sender) or {}
        master_keys = master_key_obj.get("keys") or {}
        if master_keys:
            master_key_id, master_key = next(iter(master_keys.items()))
            session["master_key_id"] = master_key_id
            session["master_key"] = master_key
        else:
            master_key = None

        current_device_key = self._get_local_device_ed25519_key()
        return peer_device_key, current_device_key, master_key, response


__all__ = ["SASVerificationFlowQRPrepareKeysMixin"]
