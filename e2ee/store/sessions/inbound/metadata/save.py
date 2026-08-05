"""Inbound-session metadata persistence."""


class CryptoStoreMegolmInboundMetadataSaveMixin:
    """Persist provenance for inbound megolm sessions."""

    def save_megolm_inbound_metadata(
        self,
        session_id: str,
        *,
        room_id: str,
        sender_key: str,
        sender_user_id: str | None = None,
        sender_claimed_keys: dict[str, str] | None = None,
        forwarding_curve25519_key_chain: list[str] | None = None,
        shared_history: bool = False,
        withheld: dict[str, str] | None = None,
    ) -> None:
        """Persist provenance and Matrix v1.19 shareability for an inbound key."""
        previous = self._megolm_inbound_meta.get(session_id)
        was_shareable = (
            isinstance(previous, dict) and previous.get("shared_history") is True
        )
        previous_sender_user_id = (
            previous.get("sender_user_id") if isinstance(previous, dict) else None
        )
        normalized_sender_user_id = self._normalize_sender_user_id(
            sender_user_id,
            previous_sender_user_id,
        )
        claimed_keys = self._normalize_sender_claimed_keys(sender_claimed_keys)
        forwarding_chain = self._normalize_forwarding_chain(
            forwarding_curve25519_key_chain
        )
        previous_withheld = (
            previous.get("withheld") if isinstance(previous, dict) else None
        )
        normalized_withheld = self._normalize_withheld(withheld, previous_withheld)
        self._megolm_inbound_meta[session_id] = {
            "room_id": room_id,
            "sender_key": sender_key,
            "sender_user_id": normalized_sender_user_id,
            "sender_claimed_keys": claimed_keys,
            "forwarding_curve25519_key_chain": forwarding_chain,
            # A session is shareable when any trusted import source says so;
            # re-importing an older copy must never downgrade that decision.
            "shared_history": was_shareable or shared_history is True,
            "withheld": normalized_withheld,
        }
        self._save_record(
            self._RECORD_MEGOLM_INBOUND_META,
            self._megolm_inbound_meta,
        )


__all__ = ["CryptoStoreMegolmInboundMetadataSaveMixin"]
