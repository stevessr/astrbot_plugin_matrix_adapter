"""Megolm inbound metadata persistence."""


class OlmMachineMegolmInboundImportPersistMixin:
    """Persist session metadata, merging stored values when available."""

    def _persist_megolm_inbound_metadata(
        self,
        session_id: str,
        *,
        room_id: str,
        sender_key: str | None,
        sender_user_id: str | None,
        sender_claimed_keys: dict[str, str] | None,
        forwarding_curve25519_key_chain: list[str] | None,
        shared_history: bool,
        withheld: dict[str, str] | None,
        metadata: dict | None = None,
    ) -> None:
        """Persist session metadata, merging stored values when available."""
        save_metadata = getattr(self.store, "save_megolm_inbound_metadata", None)
        if not callable(save_metadata):
            return
        if isinstance(metadata, dict):
            save_metadata(
                session_id,
                room_id=metadata.get("room_id", room_id),
                sender_key=metadata.get("sender_key", sender_key),
                sender_user_id=metadata.get("sender_user_id"),
                sender_claimed_keys=metadata.get("sender_claimed_keys"),
                forwarding_curve25519_key_chain=metadata.get(
                    "forwarding_curve25519_key_chain"
                ),
                shared_history=shared_history,
                withheld=withheld,
            )
        else:
            save_metadata(
                session_id,
                room_id=room_id,
                sender_key=sender_key,
                sender_user_id=sender_user_id,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
                withheld=withheld,
            )
