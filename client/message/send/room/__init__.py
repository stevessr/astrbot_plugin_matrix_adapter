"""Composable room message, event, call, and edit send operations."""

import time  # noqa: F401
from typing import Any  # noqa: F401

from .....constants import (
    M_ROOM_MESSAGE,  # noqa: F401
    MSC4310_RTC_DECLINE,  # noqa: F401
    MSGTYPE_TEXT,  # noqa: F401
    REL_TYPE_REFERENCE,  # noqa: F401
    REL_TYPE_REPLACE,  # noqa: F401
)
from ....path_utils import quote_path_segment  # noqa: F401
from ..helpers import _build_live_message_metadata  # noqa: F401
from .messages import MessageRoomContentSendMixin
from .relations import MessageRoomRelationSendMixin


class MessageRoomSendMixin(
    MessageRoomContentSendMixin,
    MessageRoomRelationSendMixin,
):
    """Send room messages, custom events, call declines, and edits."""

    pass


# Preserve direct method attributes exposed by the former mixin.
MessageRoomSendMixin.send_message = MessageRoomContentSendMixin.__dict__["send_message"]
MessageRoomSendMixin.send_room_event = MessageRoomContentSendMixin.__dict__[
    "send_room_event"
]
MessageRoomSendMixin.send_call_decline = MessageRoomRelationSendMixin.__dict__[
    "send_call_decline"
]
MessageRoomSendMixin.send_room_message = MessageRoomContentSendMixin.__dict__[
    "send_room_message"
]
MessageRoomSendMixin.edit_message = MessageRoomRelationSendMixin.__dict__[
    "edit_message"
]


__all__ = ["MessageRoomSendMixin"]
