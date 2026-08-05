"""Inbound-session metadata normalization."""

import copy
from typing import Any


class CryptoStoreMegolmInboundMetadataNormalizeMixin:
    """Normalize provenance fields for inbound megolm sessions."""

    def _normalize_sender_user_id(
        self,
        sender_user_id: str | None,
        previous_sender_user_id: str | None,
    ) -> str:
        normalized_sender_user_id = ""
        if isinstance(sender_user_id, str) and sender_user_id:
            normalized_sender_user_id = sender_user_id
        elif isinstance(previous_sender_user_id, str):
            normalized_sender_user_id = previous_sender_user_id
        return normalized_sender_user_id

    def _normalize_sender_claimed_keys(
        self,
        sender_claimed_keys: dict[str, str] | None,
    ) -> dict[str, str]:
        claimed_keys = (
            {
                str(algorithm): key
                for algorithm, key in sender_claimed_keys.items()
                if isinstance(key, str)
            }
            if isinstance(sender_claimed_keys, dict)
            else {}
        )
        return claimed_keys

    def _normalize_forwarding_chain(
        self,
        forwarding_curve25519_key_chain: list[str] | None,
    ) -> list[str]:
        forwarding_chain = (
            [key for key in forwarding_curve25519_key_chain if isinstance(key, str)]
            if isinstance(forwarding_curve25519_key_chain, list)
            else []
        )
        return forwarding_chain

    def _normalize_withheld(
        self,
        withheld: dict[str, str] | None,
        previous_withheld: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
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
        return normalized_withheld


__all__ = ["CryptoStoreMegolmInboundMetadataNormalizeMixin"]
