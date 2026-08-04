"""Cancellation of pending room-key requests."""

import secrets

from astrbot.api import logger

from .....constants import M_ROOM_KEY_REQUEST


class E2EEManagerRequestsRoomKeyCancelMixin:
    """取消已接收会话对应的待处理密钥请求。"""

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
