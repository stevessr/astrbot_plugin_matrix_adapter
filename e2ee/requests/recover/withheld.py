"""Room-key withheld notices and m.no_olm recovery signaling."""

import secrets

from astrbot.api import logger

from ....constants import M_ROOM_KEY_WITHHELD, MEGOLM_ALGO
from ...constants import (
    VALID_TO_DEVICE_WITHHELD_CODES,
    VALID_WITHHELD_CODES,
    WITHHELD_NO_OLM,
)


class E2EEManagerRequestsWithheldMixin:
    """发送和处理 Matrix room-key withheld 事件。"""

    async def _send_room_key_withheld(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str | None,
        session_id: str | None,
        code: str,
        reason: str,
    ) -> bool:
        """Tell a requesting device why a Megolm session cannot be shared.

        Args:
            sender: Requesting user ID.
            requesting_device_id: Requesting device ID.
            room_id: Room containing the requested session.
            session_id: Requested Megolm session ID.
            code: Matrix room-key withholding code.
            reason: Human-readable withholding reason.

        Returns:
            Whether the withholding event was sent successfully.
        """
        if (
            not all(
                isinstance(value, str) and value
                for value in (sender, requesting_device_id)
            )
            or code not in VALID_TO_DEVICE_WITHHELD_CODES
            or not isinstance(reason, str)
            or not reason
        ):
            return False
        if code != WITHHELD_NO_OLM and not all(
            isinstance(value, str) and value for value in (room_id, session_id)
        ):
            return False
        if not self._olm:
            return False
        content = {
            "algorithm": MEGOLM_ALGO,
            # This is the sender of the withheld event, not the device which
            # originally created the requested Megolm session.
            "sender_key": str(self._olm.curve25519_key),
            "code": code,
            "reason": reason,
        }
        if code != WITHHELD_NO_OLM:
            content["room_id"] = room_id
            content["session_id"] = session_id
        try:
            await self.client.send_to_device(
                M_ROOM_KEY_WITHHELD,
                {sender: {requesting_device_id: content}},
                secrets.token_hex(16),
            )
            return True
        except Exception as e:
            logger.debug(f"Failed to send room-key withheld event: {e}")
            return False

    async def _send_no_olm_withheld(self, user_id: str, device_id: str) -> bool:
        """Send the single mailbox-safe m.no_olm signal required by Matrix."""
        if not all(isinstance(value, str) and value for value in (user_id, device_id)):
            return False
        sent = getattr(self, "_no_olm_withheld_sent", None)
        if not isinstance(sent, set):
            sent = set()
            self._no_olm_withheld_sent = sent
        peer = (user_id, device_id)
        if peer in sent:
            return False
        if await self._send_room_key_withheld(
            user_id,
            device_id,
            None,
            None,
            WITHHELD_NO_OLM,
            "An Olm session could not be established",
        ):
            sent.add(peer)
            return True
        return False

    async def handle_room_key_withheld(self, sender: str, content: dict) -> bool:
        """Record an incoming withheld notice and recover from m.no_olm."""
        if not isinstance(content, dict) or content.get("algorithm") != MEGOLM_ALGO:
            return False
        code = content.get("code")
        sender_key = content.get("sender_key")
        reason = content.get("reason")
        if (
            code not in VALID_WITHHELD_CODES
            or not isinstance(sender_key, str)
            or not sender_key
            or (reason is not None and not isinstance(reason, str))
        ):
            return False
        room_id = content.get("room_id")
        session_id = content.get("session_id")
        if code == WITHHELD_NO_OLM:
            if room_id is not None or session_id is not None:
                return False
        elif not all(
            isinstance(value, str) and value for value in (room_id, session_id)
        ):
            return False

        records = getattr(self, "_room_key_withheld", None)
        if not isinstance(records, dict):
            records = {}
            self._room_key_withheld = records
        records[(sender, str(room_id or ""), str(session_id or ""))] = dict(content)
        if code == WITHHELD_NO_OLM:
            return await self._request_new_session(sender_key, sender)
        return True


__all__ = ["E2EEManagerRequestsWithheldMixin"]
