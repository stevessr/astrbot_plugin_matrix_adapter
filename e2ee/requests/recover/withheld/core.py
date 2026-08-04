"""Sending room-key withheld notices to requesting devices."""

import secrets

from astrbot.api import logger

from .....constants import M_ROOM_KEY_WITHHELD, MEGOLM_ALGO
from ....constants import VALID_TO_DEVICE_WITHHELD_CODES, WITHHELD_NO_OLM


class E2EEManagerRequestsWithheldCoreMixin:
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
