"""Recording incoming room-key withheld notices and recovering from m.no_olm."""

from .....constants import MEGOLM_ALGO
from ....constants import VALID_WITHHELD_CODES, WITHHELD_NO_OLM


class E2EEManagerRequestsWithheldReceiveMixin:
    """发送和处理 Matrix room-key withheld 事件。"""

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
