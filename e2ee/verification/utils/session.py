"""Verification-session identity and lifecycle guards."""

from typing import Any

from astrbot.api import logger


class SASVerificationFlowSessionGuardMixin:
    """Reject events which are not bound to the active verification flow."""

    _TERMINAL_VERIFICATION_STATES = frozenset(
        {"done", "cancelled", "handled_by_other_device"}
    )

    def _get_bound_verification_session(
        self,
        transaction_id: str,
        sender: str | None = None,
        from_device: str | None = None,
        *,
        allow_terminal: bool = False,
    ) -> dict[str, Any] | None:
        """Return the active session only when transaction and identity bindings match."""
        session = self._sessions.get(transaction_id)
        if not isinstance(session, dict):
            logger.warning(
                "[E2EE-Verify] 忽略未知 transaction 的验证事件："
                f"txn={self._mask_txn_id(transaction_id)}"
            )
            return None

        state = session.get("state")
        if not allow_terminal and state in self._TERMINAL_VERIFICATION_STATES:
            logger.debug(
                "[E2EE-Verify] 忽略终止态 verification 事件："
                f"state={state} txn={self._mask_txn_id(transaction_id)}"
            )
            return None

        expected_sender = session.get("sender")
        if sender and expected_sender and sender != expected_sender:
            logger.warning(
                "[E2EE-Verify] 忽略 sender 与 transaction 绑定不一致的验证事件："
                f"sender={self._mask_identifier(sender)} "
                f"txn={self._mask_txn_id(transaction_id)}"
            )
            return None

        expected_device = session.get("from_device") or session.get("their_device")
        if from_device and expected_device and from_device != expected_device:
            logger.warning(
                "[E2EE-Verify] 忽略 device 与 transaction 绑定不一致的验证事件："
                f"device={self._mask_identifier(from_device)} "
                f"txn={self._mask_txn_id(transaction_id)}"
            )
            return None

        return session


__all__ = ["SASVerificationFlowSessionGuardMixin"]
