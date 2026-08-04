"""Transaction id resolution for in-room verification events."""

from astrbot.api import logger

from .....constants import M_KEY_VERIFICATION_REQUEST


class SASVerificationRoomEventDispatchTxnMixin:
    """解析房间内验证事件的 transaction_id。"""

    def _resolve_in_room_transaction_id(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
        relates_to,
        msgtype: str,
    ) -> tuple[bool, str | None]:
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

        return is_verification_request, transaction_id
