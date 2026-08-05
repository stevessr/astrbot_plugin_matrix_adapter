"""Mandatory Olm plaintext claim extraction."""


class E2EEManagerDecryptOlmClaimMixin:
    """Validate the mandatory MSC4147 plaintext claims."""

    def _extract_olm_plaintext_claims(
        self,
        plaintext: object,
        event_sender: str | None,
        sender_curve25519_key: str,
    ) -> tuple | bool:
        """Return ``(claimed_ed25519, sender_device_keys)`` or ``False``."""
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
        return claimed_ed25519, plaintext.get("sender_device_keys")


__all__ = ["E2EEManagerDecryptOlmClaimMixin"]
