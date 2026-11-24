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
        is_verification_request: bool,
    ) -> bool:
        """Store room context; return True when the event must be ignored."""
        session = self._sessions.get(transaction_id)
        if session is None:
            # A verification request is the only event allowed to create an
            # in-room flow. Previously any orphan start/key/mac event created an
            # empty session before routing, defeating later existence checks.
            if not is_verification_request:
                logger.warning(
                    "[E2EE-Verify] 忽略未知 transaction 的房间内验证事件："
                    f"type={event_type} txn={self._mask_txn_id(transaction_id)}"
                )
                return True
            session = {"_room_context_only": True}
            self._sessions[transaction_id] = session

        session["room_id"] = room_id
        session["is_in_room"] = True

        # CRITICAL: Check if this session was already taken over by another device.
        # If so, ignore ALL subsequent events for this transaction (including late
        # cancellation) so a terminal session cannot be revived or rewritten.
        session_state = session.get("state")
        if session_state == "handled_by_other_device":
            logger.debug(
                f"[E2EE-Verify] 会话已由其他设备处理，忽略事件：{event_type}"
            )
            return True

        if session_state in ("done", "cancelled"):
            logger.debug(
                "[E2EE-Verify] 房间内 verification 已终止，忽略后续事件："
                f"state={session_state} type={event_type}"
            )
            return True

        return False


__all__ = ["SASVerificationRoomEventDispatchSessionMixin"]
