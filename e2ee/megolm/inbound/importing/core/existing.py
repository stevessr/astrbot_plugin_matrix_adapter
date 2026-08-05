"""Existing-session handling for Megolm inbound imports."""


class OlmMachineMegolmInboundImportExistingMixin:
    """Merge metadata and decide whether an existing session is replaceable."""

    def _handle_existing_megolm_session(
        self,
        session_id: str,
        existing,
        candidate_index: int,
        *,
        room_id: str,
        sender_key: str | None,
        sender_user_id: str | None,
        sender_claimed_keys: dict[str, str] | None,
        forwarding_curve25519_key_chain: list[str] | None,
        shared_history: bool,
        withheld: dict[str, str] | None,
    ) -> tuple:
        if existing is None:
            return (
                True,
                sender_key,
                sender_user_id,
                sender_claimed_keys,
                forwarding_curve25519_key_chain,
            )

        get_metadata = getattr(
            self.store,
            "get_megolm_inbound_metadata",
            None,
        )
        metadata = get_metadata(session_id) if callable(get_metadata) else None
        if isinstance(metadata, dict):
            if self._reject_conflicting_megolm_provenance(
                metadata,
                room_id,
                sender_key,
                sender_user_id,
                sender_claimed_keys,
            ):
                return (
                    False,
                    sender_key,
                    sender_user_id,
                    sender_claimed_keys,
                    forwarding_curve25519_key_chain,
                )
            (
                sender_key,
                sender_user_id,
                sender_claimed_keys,
                forwarding_curve25519_key_chain,
            ) = self._merge_missing_megolm_metadata_fields(
                metadata,
                sender_key,
                sender_user_id,
                sender_claimed_keys,
                forwarding_curve25519_key_chain,
            )

        existing_index = self.get_megolm_first_known_index(existing)
        if candidate_index >= existing_index:
            # Matrix only permits replacing a stored session with a
            # trusted copy that starts at a lower message index.
            self._persist_megolm_inbound_metadata(
                session_id,
                room_id=room_id,
                sender_key=sender_key,
                sender_user_id=sender_user_id,
                sender_claimed_keys=sender_claimed_keys,
                forwarding_curve25519_key_chain=forwarding_curve25519_key_chain,
                shared_history=shared_history,
                withheld=withheld,
                metadata=metadata,
            )
            return (
                False,
                sender_key,
                sender_user_id,
                sender_claimed_keys,
                forwarding_curve25519_key_chain,
            )

        return (
            True,
            sender_key,
            sender_user_id,
            sender_claimed_keys,
            forwarding_curve25519_key_chain,
        )
