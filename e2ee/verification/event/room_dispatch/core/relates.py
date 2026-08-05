"""In-room verification event context extraction."""

from astrbot.api import logger


class SASVerificationRoomEventDispatchRelatesMixin:
    """Extract relates-to context and transaction id for in-room events."""

    def _extract_in_room_event_context(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
    ) -> tuple[bool, str | None]:
        """Return (is_verification_request, transaction_id) from event content."""
        # In-room verification uses m.relates_to to link events
        relates_to = content.get("m.relates_to", {})
        msgtype = content.get("msgtype", "")

        # Debug: log the content structure
        logger.debug(
            f"[E2EE-Verify] 房间内事件内容：type={event_type}, "
            f"relates_to_keys={list(relates_to.keys()) if isinstance(relates_to, dict) else []}, msgtype={msgtype}"
        )

        # For m.key.verification.request events (either as event_type OR msgtype),
        # use event_id as transaction_id
        is_verification_request, transaction_id = self._resolve_in_room_transaction_id(
            event_type,
            sender,
            content,
            room_id,
            event_id,
            relates_to,
            msgtype,
        )
        return is_verification_request, transaction_id


__all__ = ["SASVerificationRoomEventDispatchRelatesMixin"]
