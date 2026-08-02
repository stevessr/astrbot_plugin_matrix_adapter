import time
from typing import Any


class CryptoStoreMegolmOutboundSessionsMixin:
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
