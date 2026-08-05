"""Legacy Olm sender resolution without sender_device_keys."""

from astrbot.api import logger


class E2EEManagerDecryptOlmLegacyMixin:
    """Resolve the sender device from stored or queried device keys."""

    async def _validate_olm_legacy_sender(
        self,
        event_sender: str,
        sender_curve25519_key: str,
        claimed_ed25519: str,
    ) -> bool:
        # Older senders may omit MSC4147 sender_device_keys. Resolve the exact
        # Curve25519 + Ed25519 pair from a signed /keys/query device object.
        candidates: dict = {}
        if self._store:
            get_all = getattr(self._store, "get_all_device_keys", None)
            if callable(get_all):
                all_keys = get_all()
                if isinstance(all_keys, dict):
                    candidates = all_keys.get(event_sender) or {}

        matching = self._find_validated_sender_device(
            event_sender,
            sender_curve25519_key,
            claimed_ed25519,
            candidates,
        )
        if matching:
            mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
            if callable(mark_succeeded):
                mark_succeeded(event_sender, matching[0])
            return True
        try:
            response = await self.client.query_keys({event_sender: []})
        except Exception as e:
            logger.warning(f"Unable to validate Olm sender device keys: {e}")
            return False
        candidates = (response.get("device_keys") or {}).get(event_sender) or {}
        matching = self._find_validated_sender_device(
            event_sender,
            sender_curve25519_key,
            claimed_ed25519,
            candidates,
        )
        if not matching:
            return False
        device_id, device_info = matching
        if self._store:
            self._store.save_device_keys(event_sender, device_id, device_info)
        mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
        if callable(mark_succeeded):
            mark_succeeded(event_sender, device_id)
        return True


__all__ = ["E2EEManagerDecryptOlmLegacyMixin"]
