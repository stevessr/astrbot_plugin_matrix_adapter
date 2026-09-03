"""Verification-session identity, ordering, and lifecycle guards."""

import asyncio
import time
from typing import Any

from astrbot.api import logger


class SASVerificationFlowSessionGuardMixin:
    """Reject events which are not bound to the active verification flow."""

    _TERMINAL_VERIFICATION_STATES = frozenset(
        {"done", "cancelled", "handled_by_other_device"}
    )
    _VERIFICATION_TIMEOUT_SECONDS = 10 * 60

    @staticmethod
    def _verification_monotonic() -> float:
        """Return the monotonic clock used by verification lifecycle tracking."""
        return time.monotonic()

    def _get_verification_timeout_tasks(self) -> dict[str, asyncio.Task]:
        tasks = getattr(self, "_verification_timeout_tasks", None)
        if not isinstance(tasks, dict):
            tasks = {}
            self._verification_timeout_tasks = tasks
        return tasks

    def _ensure_verification_timeout_task(self, transaction_id: str) -> None:
        """Ensure a single timeout watcher exists for an active transaction."""
        if not getattr(self, "_verification_timeout_enabled", False):
            return

        session = self._sessions.get(transaction_id)
        if not isinstance(session, dict):
            return
        if session.get("state") in self._TERMINAL_VERIFICATION_STATES:
            return

        tasks = self._get_verification_timeout_tasks()
        current = tasks.get(transaction_id)
        if current is not None and not current.done():
            return

        try:
            task = asyncio.create_task(
                self._verification_timeout_worker(transaction_id),
                name=f"matrix-verification-timeout:{transaction_id[:12]}",
            )
        except RuntimeError:
            # Some synchronous setup paths create a transaction before an event
            # loop is running. The first async send/receive will ensure the task.
            return
        tasks[transaction_id] = task

    def _initialize_verification_session_lifecycle(
        self, session: dict[str, Any], transaction_id: str
    ) -> None:
        """Start the stable 10-minute verification lifetime/idle window."""
        now = self._verification_monotonic()
        session.setdefault("_verification_created_at", now)
        session["_verification_last_activity"] = now
        self._ensure_verification_timeout_task(transaction_id)

    def _touch_verification_session(self, transaction_id: str) -> None:
        """Record a valid send/receive for the transaction idle timeout."""
        session = self._sessions.get(transaction_id)
        if not isinstance(session, dict):
            return
        if session.get("state") in self._TERMINAL_VERIFICATION_STATES:
            return

        now = self._verification_monotonic()
        session.setdefault("_verification_created_at", now)
        session["_verification_last_activity"] = now
        self._ensure_verification_timeout_task(transaction_id)

    def _stop_verification_timeout_task(self, transaction_id: str) -> None:
        """Remove and cancel a timeout watcher without cancelling itself."""
        tasks = getattr(self, "_verification_timeout_tasks", None)
        if not isinstance(tasks, dict):
            return
        task = tasks.pop(transaction_id, None)
        if task is None or task.done():
            return
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if task is not current:
            task.cancel()

    async def _verification_timeout_worker(self, transaction_id: str) -> None:
        """Cancel a verification which exceeds the stable lifetime/idle limit."""
        try:
            while True:
                session = self._sessions.get(transaction_id)
                if not isinstance(session, dict):
                    return
                if session.get("state") in self._TERMINAL_VERIFICATION_STATES:
                    return

                now = self._verification_monotonic()
                created = session.get("_verification_created_at")
                last_activity = session.get("_verification_last_activity")
                if not isinstance(created, (int, float)):
                    created = now
                    session["_verification_created_at"] = created
                if not isinstance(last_activity, (int, float)):
                    last_activity = now
                    session["_verification_last_activity"] = last_activity

                # The verification itself must complete within ten minutes. The
                # transaction id also expires after ten idle minutes. Tracking
                # both explicitly keeps the implementation faithful even though
                # the total-lifetime deadline normally wins for an active flow.
                total_deadline = float(created) + self._VERIFICATION_TIMEOUT_SECONDS
                idle_deadline = (
                    float(last_activity) + self._VERIFICATION_TIMEOUT_SECONDS
                )
                deadline = min(total_deadline, idle_deadline)
                delay = deadline - now
                if delay > 0:
                    await asyncio.sleep(delay)
                    continue

                logger.warning(
                    "[E2EE-Verify] verification 超时："
                    f"txn={self._mask_txn_id(transaction_id)}"
                )
                await self._cancel_bound_verification_session(
                    session,
                    transaction_id,
                    "m.timeout",
                    "Verification timed out",
                )

                notify = getattr(self, "_notify_admin_rooms_for_verification", None)
                if callable(notify):
                    sender = self._mask_identifier(session.get("sender"))
                    device = self._mask_identifier(
                        session.get("from_device") or session.get("their_device")
                    )
                    try:
                        await notify(
                            "Matrix 设备验证已超时并取消。\n"
                            f"用户：{sender}\n设备：{device}",
                            transaction_id,
                        )
                    except Exception as exc:
                        logger.warning(f"[E2EE-Verify] 发送超时通知失败：{exc}")
                return
        except asyncio.CancelledError:
            return
        finally:
            tasks = getattr(self, "_verification_timeout_tasks", None)
            if isinstance(tasks, dict):
                task = tasks.get(transaction_id)
                try:
                    current = asyncio.current_task()
                except RuntimeError:
                    current = None
                if task is current:
                    tasks.pop(transaction_id, None)

    async def _cancel_parallel_verification_attempts(
        self,
        sender: str,
        from_device: str,
        transaction_id: str,
        *,
        current_session: dict[str, Any] | None = None,
        room_id: str | None = None,
    ) -> bool:
        """Cancel every attempt when one device starts multiple active flows."""
        conflicts: list[tuple[str, dict[str, Any]]] = []
        for other_transaction_id, other_session in list(self._sessions.items()):
            if other_transaction_id == transaction_id:
                continue
            if not isinstance(other_session, dict):
                continue
            if other_session.get("state") in self._TERMINAL_VERIFICATION_STATES:
                continue
            if other_session.get("_room_context_only"):
                continue

            other_sender = other_session.get("sender")
            other_device = other_session.get("from_device") or other_session.get(
                "their_device"
            )
            if other_sender == sender and other_device == from_device:
                conflicts.append((other_transaction_id, other_session))

        if not conflicts:
            return False

        reason = "Multiple verification attempts from the same device"
        for other_transaction_id, other_session in conflicts:
            await self._cancel_bound_verification_session(
                other_session,
                other_transaction_id,
                "m.unexpected_message",
                reason,
            )

        if current_session is not None:
            current_session.update(
                {
                    "sender": sender,
                    "from_device": from_device,
                    "their_device": from_device,
                }
            )
            if room_id:
                current_session["room_id"] = room_id
                current_session["is_in_room"] = True
            await self._cancel_bound_verification_session(
                current_session,
                transaction_id,
                "m.unexpected_message",
                reason,
                sender=sender,
                from_device=from_device,
            )
        else:
            send_cancel = getattr(self, "_send_cancel", None)
            if callable(send_cancel):
                await send_cancel(
                    sender,
                    from_device,
                    transaction_id,
                    "m.unexpected_message",
                    reason,
                )

        return True

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
        self._stop_verification_timeout_task(transaction_id)

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
