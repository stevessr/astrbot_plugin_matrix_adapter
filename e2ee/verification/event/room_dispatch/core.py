"""In-room verification event routing and session ownership checks."""

from astrbot.api import logger

from .....constants import (
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_REQUEST,
    M_KEY_VERIFICATION_START,
)


class SASVerificationRoomEventDispatchCoreMixin:
    """解析房间内事件关系、处理设备接管并路由事件。"""

    async def handle_in_room_verification_event(
        self, event_type: str, sender: str, content: dict, room_id: str, event_id: str
    ) -> bool:
        """处理房间内验证事件"""
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

        if not transaction_id:
            logger.warning(
                f"[E2EE-Verify] 房间内验证事件缺少 transaction_id: "
                f"type={event_type}, sender={sender}"
            )
            return False

        logger.debug(
            f"[E2EE-Verify] 收到房间内验证事件：{event_type} "
            f"from={sender} room={(room_id or '')[:16]}... txn={(transaction_id or '')[:16]}..."
        )

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
                return True  # Ignore this event

        # Check if this event is from our own user
        if sender == self.user_id:
            handled = await self._handle_own_user_room_event(
                sender,
                event_type,
                content,
                transaction_id,
            )
            if handled is not None:
                return handled

        handlers = {
            M_KEY_VERIFICATION_REQUEST: self._handle_in_room_request,
            M_KEY_VERIFICATION_READY: self._handle_ready,
            M_KEY_VERIFICATION_START: self._handle_start,
            M_KEY_VERIFICATION_ACCEPT: self._handle_accept,
            M_KEY_VERIFICATION_KEY: self._handle_key,
            M_KEY_VERIFICATION_MAC: self._handle_mac,
            M_KEY_VERIFICATION_DONE: self._handle_done,
            M_KEY_VERIFICATION_CANCEL: self._handle_cancel,
        }

        # For verification requests (m.room.message with msgtype m.key.verification.request),
        # use _handle_in_room_request directly
        if is_verification_request:
            await self._handle_in_room_request(sender, content, transaction_id)
            return True

        handler = handlers.get(event_type)
        if handler:
            await handler(sender, content, transaction_id)
            return True
        return False
