"""Inbound-session metadata queries and binding."""

import copy
from typing import Any


class CryptoStoreMegolmInboundMetadataQueryMixin:
    """Read and bind inbound-session metadata."""

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


__all__ = ["CryptoStoreMegolmInboundMetadataQueryMixin"]
