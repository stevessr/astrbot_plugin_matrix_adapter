"""Throttle and purge pending room-key requests."""

import secrets


class E2EEManagerRequestsRoomKeyThrottleMixin:
    """在锁内更新待处理请求并应用节流。"""

    async def _prepare_room_key_request(
        self,
        request_key: tuple,
        recipients: set,
        now: float,
    ) -> tuple[str, float] | None:
        """Return (request_id, created_at), or None when throttled."""
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
                    return None
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

        return request_id, created_at
