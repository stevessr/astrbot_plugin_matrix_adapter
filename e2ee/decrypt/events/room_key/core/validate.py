"""m.room_key field extraction and validation."""

from astrbot.api import logger

from ......constants import MEGOLM_ALGO


class E2EEManagerDecryptRoomKeyValidateMixin:
    """Extract and validate m.room_key event fields."""

    def _extract_room_key_fields(self, event, sender_key):
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return None

        if not isinstance(event, dict):
            return None

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return None

        if not all(
            isinstance(value, str) and value
            for value in (room_id, session_id, session_key, sender_key)
        ):
            logger.warning("m.room_key 事件缺少必要字段")
            return None

        return room_id, session_id, session_key, algorithm


__all__ = ["E2EEManagerDecryptRoomKeyValidateMixin"]
