"""Megolm inbound session provenance checks and metadata backfill."""

from astrbot.api import logger


class OlmMachineMegolmInboundProvenanceMixin:
    """Validate and backfill Megolm inbound session metadata."""

    def _reject_conflicting_megolm_provenance(
        self,
        metadata: dict,
        room_id: str,
        sender_key: str | None,
        sender_user_id: str | None,
        sender_claimed_keys: dict[str, str] | None,
    ) -> bool:
        """Return True when stored provenance conflicts with the update."""
        existing_room_id = metadata.get("room_id")
        existing_sender_key = metadata.get("sender_key")
        existing_sender_user_id = metadata.get("sender_user_id")
        existing_claimed_keys = metadata.get("sender_claimed_keys")
        existing_ed25519 = (
            existing_claimed_keys.get("ed25519")
            if isinstance(existing_claimed_keys, dict)
            else None
        )
        candidate_ed25519 = (
            sender_claimed_keys.get("ed25519")
            if isinstance(sender_claimed_keys, dict)
            else None
        )
        if (
            isinstance(existing_room_id, str)
            and existing_room_id
            and existing_room_id != room_id
        ) or (
            isinstance(existing_sender_key, str)
            and existing_sender_key
            and isinstance(sender_key, str)
            and sender_key
            and existing_sender_key != sender_key
        ):
            logger.warning("Rejected Megolm update with conflicting provenance")
            return True
        if (
            isinstance(existing_sender_user_id, str)
            and existing_sender_user_id
            and isinstance(sender_user_id, str)
            and sender_user_id
            and existing_sender_user_id != sender_user_id
        ):
            logger.warning("Rejected Megolm update with a conflicting sender")
            return True
        if (
            isinstance(existing_ed25519, str)
            and existing_ed25519
            and isinstance(candidate_ed25519, str)
            and candidate_ed25519
            and existing_ed25519 != candidate_ed25519
        ):
            logger.warning("Rejected Megolm update with a conflicting signing key")
            return True
        return False

    def _merge_missing_megolm_metadata_fields(
        self,
        metadata: dict,
        sender_key: str | None,
        sender_user_id: str | None,
        sender_claimed_keys: dict[str, str] | None,
        forwarding_curve25519_key_chain: list[str] | None,
    ) -> tuple[str | None, str | None, dict[str, str] | None, list[str] | None]:
        """Backfill missing sender fields from stored metadata."""
        existing_sender_key = metadata.get("sender_key")
        existing_sender_user_id = metadata.get("sender_user_id")
        existing_claimed_keys = metadata.get("sender_claimed_keys")
        if not sender_key and isinstance(existing_sender_key, str):
            sender_key = existing_sender_key
        if not sender_user_id and isinstance(existing_sender_user_id, str):
            sender_user_id = existing_sender_user_id
        if not sender_claimed_keys and isinstance(existing_claimed_keys, dict):
            sender_claimed_keys = existing_claimed_keys
        if forwarding_curve25519_key_chain is None and isinstance(
            metadata.get("forwarding_curve25519_key_chain"),
            list,
        ):
            forwarding_curve25519_key_chain = metadata[
                "forwarding_curve25519_key_chain"
            ]
        return (
            sender_key,
            sender_user_id,
            sender_claimed_keys,
            forwarding_curve25519_key_chain,
        )
