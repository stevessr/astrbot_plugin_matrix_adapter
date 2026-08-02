"""Layered Matrix message sending mixins."""

from .device import MessageToDeviceMixin
from .helpers import (
    _build_live_message_metadata,
    _content_has_live_marker,
    _content_is_edit,
)
from .reaction import MessageReactionMixin
from .room import MessageRoomSendMixin


class MessageSendMixin(
    MessageRoomSendMixin,
    MessageReactionMixin,
    MessageToDeviceMixin,
):
    """Message sending methods for Matrix client."""

    pass


# Keep methods visible on the historical combined class for callers that
# inspect the class dictionary or use it as a direct mixin.
MessageSendMixin.send_message = MessageRoomSendMixin.send_message
MessageSendMixin.send_room_event = MessageRoomSendMixin.send_room_event
MessageSendMixin.send_call_decline = MessageRoomSendMixin.send_call_decline
MessageSendMixin.send_room_message = MessageRoomSendMixin.send_room_message
MessageSendMixin.edit_message = MessageRoomSendMixin.edit_message
MessageSendMixin.send_reaction = MessageReactionMixin.send_reaction
MessageSendMixin.send_to_device = MessageToDeviceMixin.send_to_device


__all__ = [
    "MessageSendMixin",
    "MessageRoomSendMixin",
    "MessageReactionMixin",
    "MessageToDeviceMixin",
    "_content_has_live_marker",
    "_content_is_edit",
    "_build_live_message_metadata",
]
