"""Mailbox-safe m.no_olm signaling to peers without an Olm session."""

from ....constants import WITHHELD_NO_OLM


class E2EEManagerRequestsWithheldSignalMixin:
    """发送和处理 Matrix room-key withheld 事件。"""

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
