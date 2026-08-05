"""In-room verification session takeover handling."""

from astrbot.api import logger

from ......constants import M_KEY_VERIFICATION_CANCEL


class SASVerificationRoomEventDispatchSessionMixin:
    """Prepare in-room sessions and enforce device-takeover ownership."""

    def _prepare_in_room_session(
        self,
        transaction_id: str,
        room_id: str,
        event_type: str,
    ) -> bool:
        """Store session room context; return True when the event must be ignored."""
        # Store room_id in session for in-room responses
        if transaction_id not in self._sessions:
            self._sessions[transaction_id] = {}
        self._sessions[transaction_id]["room_id"] = room_id
        self._sessions[transaction_id]["is_in_room"] = True

        # CRITICAL: Check if this session was already taken over by another device
        # If so, ignore ALL subsequent events for this transaction (except cancel)
        session_state = self._sessions[transaction_id].get("state")
        if session_state == "handled_by_other_device":
            if event_type != M_KEY_VERIFICATION_CANCEL:
                logger.debug(
                    f"[E2EE-Verify] 会话已由其他设备处理，忽略事件：{event_type}"
                )
                return True
        return False


__all__ = ["SASVerificationRoomEventDispatchSessionMixin"]
