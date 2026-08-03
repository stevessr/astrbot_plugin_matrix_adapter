"""Composable Matrix call event classification and formatting operations."""

from dataclasses import dataclass

from .classification import (
    classify_call_event,
    is_call_event_type,
    should_surface_call_event,
)
from .constants import (
    CALL_1TO1_LIFECYCLE_EVENT_TYPES,
    CALL_DECLINE_EVENT_TYPES,
    CALL_GROUP_MEMBER_EVENT_TYPES,
    CALL_GROUP_OBJECT_EVENT_TYPES,
    CALL_NOTIFY_EVENT_TYPES,
    CALL_SIGNALLING_EVENT_TYPES,
    CATEGORY_1TO1,
    CATEGORY_DECLINE,
    CATEGORY_GROUP_MEMBER,
    CATEGORY_GROUP_OBJECT,
    CATEGORY_RINGING,
    CATEGORY_SIGNALLING,
    DEFAULT_CALL_EVENT_CONFIG,
    M_RTC_DECLINE,
    MSC4310_RTC_DECLINE,
    CallEventConfig,
)
from .formatting import (
    _invite_media_kind,
    _member_has_left,
    format_call_event_text,
)

__all__ = [
    "CALL_1TO1_LIFECYCLE_EVENT_TYPES",
    "CALL_DECLINE_EVENT_TYPES",
    "CALL_GROUP_MEMBER_EVENT_TYPES",
    "CALL_GROUP_OBJECT_EVENT_TYPES",
    "CALL_NOTIFY_EVENT_TYPES",
    "CALL_SIGNALLING_EVENT_TYPES",
    "CATEGORY_1TO1",
    "CATEGORY_DECLINE",
    "CATEGORY_GROUP_MEMBER",
    "CATEGORY_GROUP_OBJECT",
    "CATEGORY_RINGING",
    "CATEGORY_SIGNALLING",
    "CallEventConfig",
    "DEFAULT_CALL_EVENT_CONFIG",
    "M_RTC_DECLINE",
    "MSC4310_RTC_DECLINE",
    "_invite_media_kind",
    "_member_has_left",
    "classify_call_event",
    "dataclass",
    "format_call_event_text",
    "is_call_event_type",
    "should_surface_call_event",
]
