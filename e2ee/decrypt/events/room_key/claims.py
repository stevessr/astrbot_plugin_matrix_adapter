"""Room-key claimed-key normalization."""


class E2EEManagerDecryptRoomKeyClaimsMixin:
    """Normalize the authenticated signing-key claims of a room key."""

    def _normalize_room_key_claims(
        self,
        sender_claimed_keys,
        forwarded_ed25519,
    ) -> dict | None:
        """Return normalized claimed keys, or None without a valid ed25519."""
        claimed_keys = sender_claimed_keys
        if isinstance(forwarded_ed25519, str) and forwarded_ed25519:
            claimed_keys = {"ed25519": forwarded_ed25519}
        if not isinstance(claimed_keys, dict):
            claimed_keys = {}
        else:
            claimed_keys = {
                str(algorithm): key
                for algorithm, key in claimed_keys.items()
                if isinstance(key, str)
            }
        if not isinstance(claimed_keys.get("ed25519"), str) or not claimed_keys.get(
            "ed25519"
        ):
            return None
        return claimed_keys
