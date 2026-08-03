"""Composable Matrix receiver message conversion operations."""

import asyncio

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType

from .....client.event_types import MatrixRoom
from .....config.plugin import get_plugin_config
from .....constants import (
    M_POLL_END,
    M_POLL_RESPONSE,
    M_POLL_START,
    MSC1767_HTML_KEY,
    MSC1767_TEXT_KEY,
    MSC3381_POLL_END,
    MSC3381_POLL_RESPONSE,
    MSC3381_POLL_START,
    MSGTYPE_AUDIO,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_REDACTION,
    MSGTYPE_TEXT,
    MSGTYPE_VIDEO,
    REL_TYPE_THREAD,
)
from .....utils.utils import MatrixUtils
from ....events import (
    BEACON_EVENT_TYPES,
    ROOM_STATE_HANDLERS,
    handle_beacon,
    handle_beacon_info,
    handle_call_event,
    handle_extensible_event,
    handle_poll_end,
    handle_poll_response,
    handle_poll_start,
    handle_unknown,
    is_call_event_type,
)
from .helpers import _has_extensible_content
from .message import MatrixReceiverMessageConvertMixin
from .system import MatrixReceiverSystemConvertMixin


class MatrixReceiverConvertOperationsMixin(
    MatrixReceiverMessageConvertMixin,
    MatrixReceiverSystemConvertMixin,
):
    """MatrixReceiver 消息转换 mixin"""

    pass


for _mixin in (
    MatrixReceiverMessageConvertMixin,
    MatrixReceiverSystemConvertMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixReceiverConvertOperationsMixin, _method_name, _method)


__all__ = [
    "AstrBotMessage",
    "BEACON_EVENT_TYPES",
    "M_POLL_END",
    "M_POLL_RESPONSE",
    "M_POLL_START",
    "MSC1767_HTML_KEY",
    "MSC1767_TEXT_KEY",
    "MSC3381_POLL_END",
    "MSC3381_POLL_RESPONSE",
    "MSC3381_POLL_START",
    "MSGTYPE_AUDIO",
    "MSGTYPE_FILE",
    "MSGTYPE_IMAGE",
    "MSGTYPE_REDACTION",
    "MSGTYPE_TEXT",
    "MSGTYPE_VIDEO",
    "MatrixReceiverConvertOperationsMixin",
    "MatrixReceiverMessageConvertMixin",
    "MatrixReceiverSystemConvertMixin",
    "MatrixRoom",
    "MatrixUtils",
    "MessageChain",
    "MessageMember",
    "MessageType",
    "REL_TYPE_THREAD",
    "ROOM_STATE_HANDLERS",
    "_has_extensible_content",
    "asyncio",
    "get_plugin_config",
    "handle_beacon",
    "handle_beacon_info",
    "handle_call_event",
    "handle_extensible_event",
    "handle_poll_end",
    "handle_poll_response",
    "handle_poll_start",
    "handle_unknown",
    "is_call_event_type",
    "logger",
]
