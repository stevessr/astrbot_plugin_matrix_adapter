from astrbot.api import logger


class E2EEManagerDecryptOlmValidateMixin:
    async def _validate_incoming_olm_plaintext(
        self,
        plaintext: object,
        event_sender: str | None,
        sender_curve25519_key: str,
    ) -> bool:
        """Apply Matrix v1.19/MSC4147 mandatory Olm plaintext checks."""
        if not isinstance(plaintext, dict) or not isinstance(event_sender, str):
            return False
        if plaintext.get("sender") != event_sender:
            return False
        if plaintext.get("recipient") != self.user_id:
            return False
        recipient_keys = plaintext.get("recipient_keys")
        if not isinstance(recipient_keys, dict) or recipient_keys.get("ed25519") != str(
            self._olm.ed25519_key
        ):
            return False
        sender_claimed_keys = plaintext.get("keys")
        if not isinstance(sender_claimed_keys, dict):
            return False
        claimed_ed25519 = sender_claimed_keys.get("ed25519")
        if not isinstance(claimed_ed25519, str) or not claimed_ed25519:
            return False
        if not isinstance(plaintext.get("type"), str) or not plaintext.get("type"):
            return False
        if not isinstance(plaintext.get("content"), dict):
            return False

        sender_device_keys = plaintext.get("sender_device_keys")
        if sender_device_keys is not None:
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
