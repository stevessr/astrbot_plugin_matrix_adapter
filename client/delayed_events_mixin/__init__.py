"""Composable MSC4140 delayed-event operations."""

import secrets
import time
from typing import Any

from ...constants import (
    MSC4140_DELAY_KEY,
    MSC4140_DELAYED_EVENTS_PATH,
    MSC4140_PARENT_DELAY_ID_KEY,
)
from ..path_utils import quote_path_segment
from .management import DelayedEventManagementMixin
from .sending import DelayedEventSendingMixin


class DelayedEventsMixin(
    DelayedEventSendingMixin,
    DelayedEventManagementMixin,
):
    """MSC4140 delayed/future events."""

    pass


# Preserve direct method attributes exposed by the former mixin.
DelayedEventsMixin.send_delayed_room_event = DelayedEventSendingMixin.__dict__[
    "send_delayed_room_event"
]
DelayedEventsMixin.send_delayed_state_event = DelayedEventSendingMixin.__dict__[
    "send_delayed_state_event"
]
DelayedEventsMixin.list_delayed_events = DelayedEventManagementMixin.__dict__[
    "list_delayed_events"
]
DelayedEventsMixin.manage_delayed_event = DelayedEventManagementMixin.__dict__[
    "manage_delayed_event"
]
DelayedEventsMixin.cancel_delayed_event = DelayedEventManagementMixin.__dict__[
    "cancel_delayed_event"
]
DelayedEventsMixin.restart_delayed_event = DelayedEventManagementMixin.__dict__[
    "restart_delayed_event"
]
DelayedEventsMixin.fire_delayed_event = DelayedEventManagementMixin.__dict__[
    "fire_delayed_event"
]


__all__ = [
    "Any",
    "DelayedEventsMixin",
    "MSC4140_DELAY_KEY",
    "MSC4140_DELAYED_EVENTS_PATH",
    "MSC4140_PARENT_DELAY_ID_KEY",
    "quote_path_segment",
    "secrets",
    "time",
]
