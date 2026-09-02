"""Composable Matrix push-rule and notification operations."""

from typing import Any

from ..path_utils import quote_path_segment
from .notifications import PushNotificationMixin
from .rules import PushRuleMixin


class PushMixin(
    PushRuleMixin,
    PushNotificationMixin,
):
    """Push rules and notifications methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
PushMixin.get_push_rules = PushRuleMixin.__dict__["get_push_rules"]
PushMixin.get_push_rule = PushRuleMixin.__dict__["get_push_rule"]
PushMixin.delete_push_rule = PushRuleMixin.__dict__["delete_push_rule"]
PushMixin.set_push_rule = PushRuleMixin.__dict__["set_push_rule"]
PushMixin.get_push_rule_actions = PushRuleMixin.__dict__["get_push_rule_actions"]
PushMixin.set_push_rule_actions = PushRuleMixin.__dict__["set_push_rule_actions"]
PushMixin.get_push_rule_enabled = PushRuleMixin.__dict__["get_push_rule_enabled"]
PushMixin.set_push_rule_enabled = PushRuleMixin.__dict__["set_push_rule_enabled"]
PushMixin.is_suppress_edits_push_rule_enabled = PushRuleMixin.__dict__[
    "is_suppress_edits_push_rule_enabled"
]
PushMixin.get_pushers = PushNotificationMixin.__dict__["get_pushers"]
PushMixin.set_pusher = PushNotificationMixin.__dict__["set_pusher"]
PushMixin.get_notifications = PushNotificationMixin.__dict__["get_notifications"]


__all__ = ["Any", "PushMixin", "quote_path_segment"]
