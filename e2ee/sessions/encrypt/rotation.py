"""Outbound-session rotation and cleanup helpers."""


class E2EEManagerSessionEncryptRotationMixin:
    def _discard_outbound_session(self, room_id: str) -> bool:
        """Discard a room session and its per-session distribution state."""
        if not self._olm:
            return False
        get_session_info = getattr(
            self._olm,
            "get_megolm_outbound_session_info",
            None,
        )
        session_info = get_session_info(room_id) if callable(get_session_info) else None
        session_id = session_info[0] if session_info else None
        discard = getattr(self._olm, "discard_megolm_outbound_session", None)
        discarded = bool(callable(discard) and discard(room_id))
        if discarded and session_id:
            share_cache = getattr(self, "_room_key_share_cache", None)
            if isinstance(share_cache, dict):
                share_cache.pop(session_id, None)
            locks = getattr(self, "_room_key_share_locks", None)
            if isinstance(locks, dict):
                locks.pop(session_id, None)  # always pop, task keeps own reference
        return discarded

    def _outbound_session_is_current(self, room_id: str, session_id: str) -> bool:
        if not self._olm:
            return False
        get_session_info = getattr(
            self._olm,
            "get_megolm_outbound_session_info",
            None,
        )
        if not callable(get_session_info):
            # Lightweight test/custom Olm shims do not expose persistence
            # metadata. The production OlmMachine always does.
            return True
        current = get_session_info(room_id)
        return bool(current and current[0] == session_id)
