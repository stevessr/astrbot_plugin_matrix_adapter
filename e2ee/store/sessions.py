"""
Sessions mixin for CryptoStore — Olm/Megolm session and device-key accessors.
"""

import copy
import time
from typing import Any

from astrbot.api import logger

# Maximum Megolm message indices to track per session for replay protection.
# Older entries are evicted; a Megolm session ratchets forward monotonically
# so old indices cannot be reused for new attacks after the ratchet has
# advanced past them.
_MAX_REPLAY_INDEXES_PER_SESSION = 10_000


class CryptoStoreSessionsMixin:
    """Session access layer for E2EE crypto store."""

    # ========== Olm 账户 ==========

    def get_account_pickle(self) -> str | None:
        """获取 Olm 账户的 pickle"""
        return self._account_pickle

    def save_account_pickle(self, pickle: str):
        """保存 Olm 账户的 pickle"""
        self._account_pickle = pickle
        self._save_record(self._RECORD_ACCOUNT, {"pickle": pickle})

    def clear_account_pickle(self):
        """删除持久化的 Olm 账户 pickle。"""
        self._account_pickle = None
        self._delete_record(self._RECORD_ACCOUNT)

    # ========== Olm 会话 ==========

    def get_olm_sessions(self, sender_key: str) -> list[str]:
        """获取与特定发送者的 Olm 会话列表"""
        return self._olm_sessions.get(sender_key, [])

    def add_olm_session(self, sender_key: str, session_pickle: str):
        """添加 Olm 会话"""
        if sender_key not in self._olm_sessions:
            self._olm_sessions[sender_key] = []
        self._olm_sessions[sender_key].append(session_pickle)
        self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def update_olm_session(self, sender_key: str, index: int, session_pickle: str):
        """更新 Olm 会话"""
        if sender_key in self._olm_sessions and index < len(
            self._olm_sessions[sender_key]
        ):
            self._olm_sessions[sender_key][index] = session_pickle
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def replace_olm_sessions(self, sender_key: str, session_pickles: list[str]) -> None:
        """Persist Olm sessions in most-recently-received order."""
        self._olm_sessions[sender_key] = list(session_pickles)
        self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def clear_olm_sessions(self, sender_key: str):
        """清除与特定发送者的所有 Olm 会话"""
        if sender_key in self._olm_sessions:
            del self._olm_sessions[sender_key]
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    # ========== Megolm 入站会话 ==========

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

    # ========== Megolm 出站会话 ==========

    def get_megolm_outbound(self, room_id: str) -> str | None:
        """获取房间的 Megolm 出站会话"""
        return self._megolm_outbound.get(room_id)

    def save_megolm_outbound(self, room_id: str, session_pickle: str):
        """保存房间的 Megolm 出站会话"""
        self._megolm_outbound[room_id] = session_pickle
        self._save_record(self._RECORD_MEGOLM_OUTBOUND, self._megolm_outbound)

    def save_megolm_outbound_metadata(
        self,
        room_id: str,
        session_id: str,
        *,
        shared_history: bool,
        created_at_ms: int | None = None,
        message_count: int = 0,
    ) -> None:
        """Persist shareability and rotation state for an outbound session."""
        self._megolm_outbound_meta[room_id] = {
            "session_id": session_id,
            "shared_history": bool(shared_history),
            "created_at_ms": (
                created_at_ms
                if type(created_at_ms) is int and created_at_ms >= 0
                else int(time.time() * 1000)
            ),
            "message_count": max(0, int(message_count)),
        }
        self._save_record(
            self._RECORD_MEGOLM_OUTBOUND_META,
            self._megolm_outbound_meta,
        )

    def get_megolm_outbound_metadata(self, room_id: str) -> dict[str, Any] | None:
        """Return a defensive copy of outbound-session metadata."""
        metadata = self._megolm_outbound_meta.get(room_id)
        return dict(metadata) if isinstance(metadata, dict) else None

    def record_megolm_outbound_message(self, room_id: str, session_id: str) -> bool:
        """Increment the persisted message count for the current session."""
        metadata = self._megolm_outbound_meta.get(room_id)
        if not isinstance(metadata, dict) or metadata.get("session_id") != session_id:
            return False
        count = metadata.get("message_count")
        metadata["message_count"] = (
            count + 1 if type(count) is int and count >= 0 else 1
        )
        self._save_record(
            self._RECORD_MEGOLM_OUTBOUND_META,
            self._megolm_outbound_meta,
        )
        return True

    def delete_megolm_outbound(self, room_id: str) -> None:
        """Discard a room's outbound session while retaining inbound history."""
        self._megolm_outbound.pop(room_id, None)
        self._megolm_outbound_meta.pop(room_id, None)
        self._save_record(self._RECORD_MEGOLM_OUTBOUND, self._megolm_outbound)
        self._save_record(
            self._RECORD_MEGOLM_OUTBOUND_META,
            self._megolm_outbound_meta,
        )

    def get_megolm_outbound_rooms(self) -> list[str]:
        """获取所有已持久化的 Megolm 出站会话房间 ID"""
        return list(self._megolm_outbound.keys())

    # ========== 设备密钥 ==========

    def get_device_keys(
        self, user_id: str, device_id: str | None = None
    ) -> dict[str, dict] | dict[str, str]:
        """获取用户的所有设备密钥"""
        user_keys = self._device_keys.get(user_id, {})
        if device_id is None:
            return user_keys

        raw_device_keys = user_keys.get(device_id, {})
        if not isinstance(raw_device_keys, dict):
            return {}

        keys_obj = raw_device_keys.get("keys", {})
        if not isinstance(keys_obj, dict):
            keys_obj = {}

        curve25519 = keys_obj.get(f"curve25519:{device_id}", "")
        ed25519 = keys_obj.get(f"ed25519:{device_id}", "")
        if not curve25519 and not ed25519:
            return {}

        return {
            "curve25519": curve25519,
            "ed25519": ed25519,
        }

    def save_device_keys(self, user_id: str, device_id: str, keys: dict):
        """保存设备密钥"""
        if user_id not in self._device_keys:
            self._device_keys[user_id] = {}
        self._device_keys[user_id][device_id] = keys
        self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def replace_user_device_keys(self, user_id: str, devices: dict[str, dict]) -> None:
        """Replace a user's tracked list after a complete /keys/query result."""
        self._device_keys[user_id] = dict(devices)
        self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def delete_user_device_keys(self, user_id: str) -> None:
        """Forget device keys for a user no longer sharing encrypted rooms."""
        if self._device_keys.pop(user_id, None) is not None:
            self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def get_all_device_keys(self) -> dict[str, dict]:
        """获取所有已知的设备密钥"""
        return self._device_keys