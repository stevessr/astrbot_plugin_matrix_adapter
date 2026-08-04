"""Outgoing Matrix room-key request lifecycle."""

import secrets
import time

from astrbot.api import logger

from .....constants import M_ROOM_KEY_REQUEST, MEGOLM_ALGO


class E2EEManagerRequestsRoomKeyCoreMixin:
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

        throttled = await self._prepare_room_key_request(
            request_key,
            recipients,
            now,
        )
        if throttled is None:
            return False
        request_id, created_at = throttled

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
