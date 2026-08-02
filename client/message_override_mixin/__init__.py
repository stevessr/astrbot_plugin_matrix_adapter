"""Composable message hook registration, dispatch, and transport wrappers."""

import inspect
from typing import Any

from astrbot.api import logger

from .dispatch import MessageOverrideDispatchMixin
from .hooks import MessageOverrideHooksMixin
from .registry import MessageOverrideRegistryMixin
from .transport import MessageOverrideTransportMixin


class MessageOverrideMixin(
    MessageOverrideRegistryMixin,
    MessageOverrideDispatchMixin,
    MessageOverrideHooksMixin,
    MessageOverrideTransportMixin,
):
    """Overridable hooks around message send/fetch.

    组合进 ``MatrixHTTPClient`` 时必须排在 ``RoomMixin`` 与 ``MessageMixin``
    之前，``super()`` 才能沿 MRO 落到真正发起 HTTP 的实现上。
    """

    pass


# Preserve direct attributes exposed by the former mixin.
MessageOverrideMixin.HOOK_METHODS = MessageOverrideRegistryMixin.HOOK_METHODS
MessageOverrideMixin.message_hooks = MessageOverrideRegistryMixin.__dict__[
    "message_hooks"
]
MessageOverrideMixin.register_message_hook = MessageOverrideRegistryMixin.__dict__[
    "register_message_hook"
]
MessageOverrideMixin.unregister_message_hook = MessageOverrideRegistryMixin.__dict__[
    "unregister_message_hook"
]
MessageOverrideMixin._transform_via_hooks = MessageOverrideDispatchMixin.__dict__[
    "_transform_via_hooks"
]
MessageOverrideMixin._short_circuit_via_hooks = MessageOverrideDispatchMixin.__dict__[
    "_short_circuit_via_hooks"
]
MessageOverrideMixin.before_send_message = MessageOverrideHooksMixin.__dict__[
    "before_send_message"
]
MessageOverrideMixin.after_send_message = MessageOverrideHooksMixin.__dict__[
    "after_send_message"
]
MessageOverrideMixin.before_get_event = MessageOverrideHooksMixin.__dict__[
    "before_get_event"
]
MessageOverrideMixin.after_get_event = MessageOverrideHooksMixin.__dict__[
    "after_get_event"
]
MessageOverrideMixin.before_room_messages = MessageOverrideHooksMixin.__dict__[
    "before_room_messages"
]
MessageOverrideMixin.after_room_messages = MessageOverrideHooksMixin.__dict__[
    "after_room_messages"
]
MessageOverrideMixin.send_message = MessageOverrideTransportMixin.__dict__[
    "send_message"
]
MessageOverrideMixin.get_event = MessageOverrideTransportMixin.__dict__["get_event"]
MessageOverrideMixin.room_messages = MessageOverrideTransportMixin.__dict__[
    "room_messages"
]


__all__ = ["Any", "MessageOverrideMixin", "inspect", "logger"]
