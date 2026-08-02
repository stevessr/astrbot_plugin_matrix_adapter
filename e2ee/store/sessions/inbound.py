import copy
from typing import Any

# Maximum Megolm message indices to track per session for replay protection.
# Older entries are evicted; a Megolm session ratchets forward monotonically
# so old indices cannot be reused for new attacks after the ratchet has
# advanced past them.
_MAX_REPLAY_INDEXES_PER_SESSION = 10_000


class CryptoStoreMegolmInboundSessionsMixin:
    def get_megolm_inbound(self, session_id: str) -> str | None:
        """获取 Megolm 入站会话"""
        return self._megolm_inbound.get(session_id)

    def get_megolm_inbound_ids(self) -> list[str]:
        """返回全部 Megolm 入站会话 ID 的快照。"""
        return list(self._megolm_inbound)

    def save_megolm_inbound(self, session_id: str, session_pickle: str):
        """保存 Megolm 入站会话"""
        self._megolm_inbound[session_id] = session_pickle
        self._save_record(self._RECORD_MEGOLM_INBOUND, self._megolm_inbound)

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

    def has_megolm_inbound(self, session_id: str) -> bool:
        """检查是否存在指定 Megolm 入站会话"""
        return session_id in self._megolm_inbound

    def get_megolm_inbound_count(self) -> int:
        """获取本地 Megolm 入站会话数量"""
        return len(self._megolm_inbound)
