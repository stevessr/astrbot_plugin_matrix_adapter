"""Composable Matrix receiver message conversion operations."""

from .operations import (
    BEACON_EVENT_TYPES,
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
    ROOM_STATE_HANDLERS,
    AstrBotMessage,
    MatrixReceiverConvertOperationsMixin,
    MatrixRoom,
    MatrixUtils,
    MessageChain,
    MessageMember,
    MessageType,
    _has_extensible_content,
    asyncio,
    get_plugin_config,
    handle_beacon,
    handle_beacon_info,
    handle_call_event,
    handle_extensible_event,
    handle_poll_end,
    handle_poll_response,
    handle_poll_start,
    handle_unknown,
    is_call_event_type,
    logger,
)


class MatrixReceiverConvertMixin(MatrixReceiverConvertOperationsMixin):
    """MatrixReceiver 消息转换 mixin"""

    pass


# Preserve direct method attributes exposed by the former mixin.
for _method_name in ("convert_message", "convert_system_event"):
    setattr(
        MatrixReceiverConvertMixin,
        _method_name,
        MatrixReceiverConvertOperationsMixin.__dict__[_method_name],
    )


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
    "MatrixReceiverConvertMixin",
    "MatrixReceiverConvertOperationsMixin",
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
