"""Composable Matrix receipts, event operations, and typing helpers."""

import json
import time
from typing import Any

from ....constants import (
    DEFAULT_TIMEOUT_MS_30000,
    M_ROOM_REDACTION,
    MSC4446_ALLOW_BACKWARD,
)
from ...path_utils import quote_path_segment
from .events import MessageEventOperationsMixin
from .read import MessageReadReceiptsMixin
from .typing import MessageTypingMixin


class MessageReceiptsMixin(
    MessageReadReceiptsMixin,
    MessageEventOperationsMixin,
    MessageTypingMixin,
):
    """Message receipt, redaction, and context methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
MessageReceiptsMixin.send_read_receipt = MessageReadReceiptsMixin.__dict__[
    "send_read_receipt"
]
MessageReceiptsMixin.send_read_receipt_private = MessageReadReceiptsMixin.__dict__[
    "send_read_receipt_private"
]
MessageReceiptsMixin.send_read_markers = MessageReadReceiptsMixin.__dict__[
    "send_read_markers"
]
MessageReceiptsMixin.send_fully_read_receipt = MessageReadReceiptsMixin.__dict__[
    "send_fully_read_receipt"
]
MessageReceiptsMixin.redact_event = MessageEventOperationsMixin.__dict__["redact_event"]
MessageReceiptsMixin.report_event = MessageEventOperationsMixin.__dict__["report_event"]
MessageReceiptsMixin.report_room = MessageEventOperationsMixin.__dict__["report_room"]
MessageReceiptsMixin.report_user = MessageEventOperationsMixin.__dict__["report_user"]
MessageReceiptsMixin.get_event_context = MessageEventOperationsMixin.__dict__[
    "get_event_context"
]
MessageReceiptsMixin.get_event_relations = MessageEventOperationsMixin.__dict__[
    "get_event_relations"
]
MessageReceiptsMixin.set_typing = MessageTypingMixin.__dict__["set_typing"]


__all__ = [
    "Any",
    "DEFAULT_TIMEOUT_MS_30000",
    "M_ROOM_REDACTION",
    "MSC4446_ALLOW_BACKWARD",
    "MessageReceiptsMixin",
    "json",
    "quote_path_segment",
    "time",
]
