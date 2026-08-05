"""Stalk-archive recording for inbound callbacks."""

import time

from ...archive import _append_stalk_archive


def _record_stalk_archive(abm, event, sender_id: str, sender_name: str):
    record = {
        "ts": int(time.time() * 1000),
        "room_id": abm.session_id,
        "event_id": getattr(event, "event_id", ""),
        "sender_id": sender_id,
        "sender_name": sender_name,
        "message_str": abm.message_str,
        "message": abm.message,
        "raw_message": abm.raw_message,
    }
    _append_stalk_archive(abm.session_id, record)


__all__ = ["_record_stalk_archive"]
