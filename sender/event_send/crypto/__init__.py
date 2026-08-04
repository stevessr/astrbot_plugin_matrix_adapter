"""Streaming encryption helpers for Matrix event sending."""

from astrbot.api import logger

from ....constants import M_ROOM_ENCRYPTED, M_ROOM_MESSAGE, REL_TYPE_REPLACE
from ...events.common import _copy_cleartext_relates_to
from .edits import edit_message_encrypted, edit_message_plain
from .messages import send_message_encrypted, send_message_plain
from .payload import _encrypted_payload_without_relation, check_encrypted_room

__all__ = [
    "M_ROOM_ENCRYPTED",
    "M_ROOM_MESSAGE",
    "REL_TYPE_REPLACE",
    "_copy_cleartext_relates_to",
    "_encrypted_payload_without_relation",
    "check_encrypted_room",
    "edit_message_encrypted",
    "edit_message_plain",
    "logger",
    "send_message_encrypted",
    "send_message_plain",
]
