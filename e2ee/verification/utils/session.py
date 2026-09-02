"""Verification-session identity, ordering, and lifecycle guards."""

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

    async def _send_unknown_transaction_cancel(
        self,
        sender: str,
        transaction_id: str,
        from_device: str | None = None,
    ) -> None:
        """Tell a to-device peer that a non-start event references no active flow."""
        target_device = from_device or "*"
        send_cancel = getattr(self, "_send_cancel", None)
        if not callable(send_cancel):
            return
        await send_cancel(
            sender,
            target_device,
            transaction_id,
            "m.unknown_transaction",
            "Unknown verification transaction",
        )

    async def _cancel_bound_verification_session(
        self,
        session: dict[str, Any],
        transaction_id: str,
        code: str,
        reason: str,
        *,
        sender: str | None = None,
        from_device: str | None = None,
    ) -> None:
        """Cancel a known active flow without ever reviving a terminal transaction."""
        if session.get("state") in self._TERMINAL_VERIFICATION_STATES:
            return

        session["state"] = "cancelled"
        session["cancel_code"] = code
        session["cancel_reason"] = reason

        if session.get("is_in_room") and session.get("room_id"):
            send_room_cancel = getattr(self, "_send_in_room_cancel", None)
            if callable(send_room_cancel):
                await send_room_cancel(
                    session["room_id"],
                    transaction_id,
                    code,
                    reason,
                )
            return

        peer_user = sender or session.get("sender") or ""
        peer_device = (
            from_device
            or session.get("from_device")
            or session.get("their_device")
            or "*"
        )
        send_cancel = getattr(self, "_send_cancel", None)
        if peer_user and callable(send_cancel):
            await send_cancel(
                peer_user,
                peer_device,
                transaction_id,
                code,
                reason,
            )

    async def _reject_unexpected_verification_event(
        self,
        session: dict[str, Any],
        transaction_id: str,
        event_name: str,
        *,
        sender: str | None = None,
        from_device: str | None = None,
    ) -> None:
        """Cancel an active flow when a verification event arrives out of sequence."""
        logger.warning(
            "[E2EE-Verify] verification 事件顺序无效："
            f"event={event_name} state={session.get('state')} "
            f"txn={self._mask_txn_id(transaction_id)}"
        )
        await self._cancel_bound_verification_session(
            session,
            transaction_id,
            "m.unexpected_message",
            f"Unexpected {event_name} for the current verification state",
            sender=sender,
            from_device=from_device,
        )


__all__ = ["SASVerificationFlowSessionGuardMixin"]
