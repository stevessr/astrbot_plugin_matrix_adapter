"""Megolm message-index replay protection."""

# Maximum Megolm message indices to track per session for replay protection.
# Older entries are evicted; a Megolm session ratchets forward monotonically
# so old indices cannot be reused for new attacks after the ratchet has
# advanced past them.
_MAX_REPLAY_INDEXES_PER_SESSION = 10_000


class CryptoStoreMegolmInboundSessionsReplayMixin:
    def check_and_record_megolm_message_index(
        self,
        session_id: str,
        message_index: int,
        event_identifier: str,
    ) -> bool:
        """Persist Megolm replay state; allow only the same event at an index."""
        if (
            not isinstance(session_id, str)
            or not session_id
            or type(message_index) is not int
            or message_index < 0
            or not isinstance(event_identifier, str)
            or not event_identifier
        ):
            return False
        with self._megolm_replay_lock:
            indexes = self._megolm_replay.setdefault(session_id, {})
            index_key = str(message_index)
            previous = indexes.get(index_key)
            if previous is not None:
                return previous == event_identifier
            indexes[index_key] = event_identifier

            # Evict oldest entries when per-session limit is exceeded
            # to prevent unbounded memory growth.
            if len(indexes) > _MAX_REPLAY_INDEXES_PER_SESSION:
                for k in sorted(indexes, key=int)[:-_MAX_REPLAY_INDEXES_PER_SESSION]:
                    del indexes[k]

            self._save_record(self._RECORD_MEGOLM_REPLAY, self._megolm_replay)
        return True
