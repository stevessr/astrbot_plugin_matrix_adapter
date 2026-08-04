"""Megolm inbound-session provenance and metadata storage."""

import copy
from typing import Any


class CryptoStoreMegolmInboundSessionsMetadataMixin:
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
        normalized_sender_user_id = ""
        if isinstance(sender_user_id, str) and sender_user_id:
            normalized_sender_user_id = sender_user_id
        elif isinstance(previous_sender_user_id, str):
            normalized_sender_user_id = previous_sender_user_id
        claimed_keys = (
            {
                str(algorithm): key
                for algorithm, key in sender_claimed_keys.items()
                if isinstance(key, str)
            }
            if isinstance(sender_claimed_keys, dict)
            else {}
        )
        forwarding_chain = (
            [key for key in forwarding_curve25519_key_chain if isinstance(key, str)]
            if isinstance(forwarding_curve25519_key_chain, list)
            else []
        )
        previous_withheld = (
            previous.get("withheld") if isinstance(previous, dict) else None
        )
        normalized_withheld = (
            copy.deepcopy(previous_withheld)
            if isinstance(previous_withheld, dict)
            else None
        )
        if withheld == {}:
            normalized_withheld = None
        elif (
            isinstance(withheld, dict)
            and isinstance(withheld.get("code"), str)
            and isinstance(withheld.get("reason"), str)
        ):
            normalized_withheld = {
                "code": withheld["code"],
                "reason": withheld["reason"],
            }
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

    def get_megolm_inbound_metadata(self, session_id: str) -> dict[str, Any] | None:
        """Return a defensive copy of stored inbound-session metadata."""
        metadata = self._megolm_inbound_meta.get(session_id)
        return copy.deepcopy(metadata) if isinstance(metadata, dict) else None

    def bind_megolm_inbound_sender_user(self, session_id: str, user_id: str) -> bool:
        """Persist a validated timeline sender for a legacy/forwarded session."""
        metadata = self._megolm_inbound_meta.get(session_id)
        if (
            not isinstance(metadata, dict)
            or not isinstance(user_id, str)
            or not user_id
        ):
            return False
        existing = metadata.get("sender_user_id")
        if isinstance(existing, str) and existing:
            return existing == user_id
        metadata["sender_user_id"] = user_id
        self._save_record(
            self._RECORD_MEGOLM_INBOUND_META,
            self._megolm_inbound_meta,
        )
        return True
