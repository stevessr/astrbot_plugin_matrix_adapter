"""Direct to-device verification event dispatch."""

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


class SASVerificationEventDispatchMixin:
    """将 to-device 验证事件路由到对应 flow handler。"""

    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """处理验证事件"""
        transaction_id = content.get("transaction_id")

        if not transaction_id:
            logger.warning("[E2EE-Verify] 缺少 transaction_id，忽略事件")
            return False

        logger.debug(
            f"[E2EE-Verify] 收到验证事件：{event_type} "
            f"from={sender} txn={transaction_id}"
        )
        logger.debug(f"[E2EE-Verify] 事件内容键：{list(content.keys())}")

        handlers = {
            M_KEY_VERIFICATION_REQUEST: self._handle_request,
            M_KEY_VERIFICATION_READY: self._handle_ready,
            M_KEY_VERIFICATION_START: self._handle_start,
            M_KEY_VERIFICATION_ACCEPT: self._handle_accept,
            M_KEY_VERIFICATION_KEY: self._handle_key,
            M_KEY_VERIFICATION_MAC: self._handle_mac,
            M_KEY_VERIFICATION_DONE: self._handle_done,
            M_KEY_VERIFICATION_CANCEL: self._handle_cancel,
        }

        handler = handlers.get(event_type)
        if not handler:
            return False

        if event_type == M_KEY_VERIFICATION_REQUEST:
            await handler(sender, content, transaction_id)
            return True

        raw_session = self._sessions.get(transaction_id)

        # Matrix keeps support for the deprecated to-device standalone START so
        # older peers can still begin SAS. START is therefore the only follow-up
        # event allowed to establish a missing to-device transaction.
        if event_type == M_KEY_VERIFICATION_START and not isinstance(raw_session, dict):
            await handler(sender, content, transaction_id)
            return True

        # Never answer an unknown cancellation with another cancellation: doing
        # so can create an error loop between clients.
        if event_type == M_KEY_VERIFICATION_CANCEL and not isinstance(
            raw_session, dict
        ):
            return True

        session = self._get_bound_verification_session(
            transaction_id,
            sender,
            content.get("from_device"),
        )
        if session is None:
            # A terminal transaction is intentionally silent. For a missing or
            # identity-mismatched active flow, report unknown_transaction without
            # mutating the legitimate session. Some verification events do not
            # carry from_device, so send-to-device wildcard is used in that case.
            if isinstance(raw_session, dict) and raw_session.get(
                "state"
            ) in self._TERMINAL_VERIFICATION_STATES:
                return True
            await self._send_unknown_transaction_cancel(
                sender,
                transaction_id,
                content.get("from_device"),
            )
            return True

        self._touch_verification_session(transaction_id)
        await handler(sender, content, transaction_id)
        return True


__all__ = ["SASVerificationEventDispatchMixin"]
