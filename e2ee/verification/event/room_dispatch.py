"""In-room verification event routing and session ownership checks."""

from astrbot.api import logger

from ....constants import (
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_READY,
    M_KEY_VERIFICATION_REQUEST,
    M_KEY_VERIFICATION_START,
)


class SASVerificationRoomEventDispatchMixin:
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
        is_verification_request = (
            event_type == M_KEY_VERIFICATION_REQUEST
            or msgtype == "m.key.verification.request"
        )

        if is_verification_request:
            transaction_id = event_id
        else:
            # For other events, get transaction_id from m.relates_to
            # Matrix spec: in-room verification events use m.reference relationship
            transaction_id = relates_to.get("event_id") or content.get("transaction_id")

            # 如果 relates_to 中没有 event_id，尝试查找已有的验证会话
            if not transaction_id:
                # 尝试根据发送者和房间查找活跃的验证会话
                # 可能是：1. sender 是会话发起者 2. sender 是我们发起验证的目标设备的用户
                for txn_id, session in self._sessions.items():
                    if session.get("state") in ("done", "cancelled"):
                        continue
                    session_room = session.get("room_id")
                    session_sender = session.get("sender")
                    # 匹配条件：同一房间，且 sender 与会话相关（是发起者或是我们作为发起者时的目标）
                    if session_room == room_id and (
                        session_sender == sender  # sender 是会话发起者
                        or sender == self.user_id  # 或者是我们自己的其他设备发送的
                    ):
                        transaction_id = txn_id
                        logger.debug(
                            "[E2EE-Verify] 从活跃会话推断 transaction_id: "
                            f"{(txn_id or '')[:16]}..."
                        )
                        break

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
            from_device = content.get("from_device")

            # Skip our own key/mac/done/accept events (these are echoes of what we sent)
            # We only need to process these events from the OTHER party
            if event_type in (
                M_KEY_VERIFICATION_KEY,
                M_KEY_VERIFICATION_MAC,
                M_KEY_VERIFICATION_DONE,
                M_KEY_VERIFICATION_ACCEPT,
            ):
                logger.debug(f"[E2EE-Verify] 跳过自己发送的事件：{event_type}")
                return True  # Ignore our own echoed events

            if from_device and from_device != self.device_id:
                # 只有当事件明确表明另一个设备正在进行交互时（例如 ready/start/accept），我们才退出
                # 忽略 request 事件（因为那是发起请求，不代表接管）
                if event_type not in (
                    M_KEY_VERIFICATION_REQUEST,
                    M_KEY_VERIFICATION_CANCEL,
                ):
                    logger.info(
                        "[E2EE-Verify] 检测到其他设备 "
                        f"{from_device} 正在处理验证 txn={(transaction_id or '')[:8]}...，本设备将静默退出"
                    )
                    # 标记会话为已由其他设备处理，停止本地处理
                    if transaction_id in self._sessions:
                        self._sessions[transaction_id]["state"] = (
                            "handled_by_other_device"
                        )
                    return True  # 已处理（忽略）

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


__all__ = ["SASVerificationRoomEventDispatchMixin"]
