"""Outgoing Matrix room-key request lifecycle."""

import secrets
import time

from astrbot.api import logger

from ....constants import M_ROOM_KEY_REQUEST, MEGOLM_ALGO


class E2EEManagerRequestsRoomKeyMixin:
    """发送、节流和取消 m.room_key_request。"""

    async def _request_room_key(
        self,
        room_id: str,
        session_id: str,
        sender_key: str | None,
        sender: str | None = None,
    ) -> bool:
        """
        发送 m.room_key_request 请求密钥

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者的 curve25519 密钥

        Returns:
            Whether a request was sent. Throttled duplicate requests return False.
        """
        if not room_id or not session_id:
            logger.warning("Skipping room-key request without room_id or session_id")
            return False

        request_key = (room_id, session_id)
        now = time.monotonic()
        # Matrix key requests are restricted to verified devices of our own
        # user. The deprecated sender fields are not an authorization source.
        recipients = {self.user_id}
        if sender and sender != self.user_id:
            recipients.add(sender)

        async with self._room_key_request_lock:
            expiry = self._room_key_request_expiry_sec
            for pending_key, pending in list(self._pending_room_key_requests.items()):
                if now - float(pending.get("created_at", now)) >= expiry:
                    self._pending_room_key_requests.pop(pending_key, None)

            pending = self._pending_room_key_requests.get(request_key)
            if pending:
                pending_recipients = pending.get("recipients")
                if isinstance(pending_recipients, set):
                    recipients.update(pending_recipients)
                if (
                    now - float(pending.get("last_sent_at", 0.0))
                    < self._room_key_request_retry_interval_sec
                ):
                    return False
                request_id = str(pending["request_id"])
                created_at = float(pending.get("created_at", now))
            else:
                request_id = secrets.token_hex(16)
                created_at = now

            self._pending_room_key_requests[request_key] = {
                "request_id": request_id,
                "recipients": recipients,
                "created_at": created_at,
                "last_sent_at": now,
            }

        content = {
            "action": "request",
            "body": {
                "algorithm": MEGOLM_ALGO,
                "room_id": room_id,
                "sender_key": sender_key or "",
                "session_id": session_id,
            },
            "request_id": request_id,
            "requesting_device_id": self.device_id,
        }
        messages = {user_id: {"*": content} for user_id in sorted(recipients)}

        try:
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                messages,
                secrets.token_hex(16),
            )
            logger.info(
                f"Sent room-key request: room={room_id[:16]}... "
                f"session={session_id[:8]}... recipients={len(recipients)}"
            )
            return True
        except Exception as e:
            async with self._room_key_request_lock:
                current = self._pending_room_key_requests.get(request_key)
                if current and current.get("request_id") == request_id:
                    current["last_sent_at"] = 0.0
            logger.warning(f"Failed to send room-key request: {e}")
            return False

    async def _cancel_room_key_request(self, room_id: str, session_id: str) -> bool:
        """Cancel a pending room-key request after the session is received.

        Args:
            room_id: Room containing the Megolm session.
            session_id: Megolm session identifier.

        Returns:
            Whether a cancellation was sent successfully.
        """
        request_key = (room_id, session_id)
        async with self._room_key_request_lock:
            pending = self._pending_room_key_requests.get(request_key)
        if not pending:
            return False

        recipients = pending.get("recipients")
        if not isinstance(recipients, set) or not recipients:
            return False
        content = {
            "action": "request_cancellation",
            "request_id": str(pending["request_id"]),
            "requesting_device_id": self.device_id,
        }
        try:
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                {user_id: {"*": content} for user_id in sorted(recipients)},
                secrets.token_hex(16),
            )
            async with self._room_key_request_lock:
                current = self._pending_room_key_requests.get(request_key)
                if current and current.get("request_id") == pending.get("request_id"):
                    self._pending_room_key_requests.pop(request_key, None)
            logger.debug(f"Cancelled room-key request: session={session_id[:8]}...")
            return True
        except Exception as e:
            logger.debug(f"Failed to cancel room-key request: {e}")
            return False


__all__ = ["E2EEManagerRequestsRoomKeyMixin"]
