"""Outbound session resolution for room-key sharing."""

from astrbot.api import logger


class E2EEManagerSessionShareKeysSessionMixin:
    """Resolve the outbound Megolm session to share."""

    def _resolve_share_session(
        self,
        room_id: str,
        session_id: str | None,
        session_key: str | None,
    ) -> tuple[str, str] | None:
        """Return ``(session_id, session_key)`` or ``None`` when unavailable."""
        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            session_info = self._olm.get_megolm_outbound_session_info(room_id)
            if not session_info:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return None
            session_id, session_key = session_info
        return session_id, session_key


__all__ = ["E2EEManagerSessionShareKeysSessionMixin"]
