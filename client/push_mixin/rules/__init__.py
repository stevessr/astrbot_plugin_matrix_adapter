"""Matrix push-rule operations."""

from .query import PushRuleQueryMixin
from .update import PushRuleUpdateMixin


class PushRuleMixin(
    PushRuleQueryMixin,
    PushRuleUpdateMixin,
):
    """Create, inspect, and update Matrix push rules."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    PushRuleQueryMixin,
    PushRuleUpdateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(PushRuleMixin, _method_name, _method)


__all__ = [
    "PushRuleMixin",
    "PushRuleQueryMixin",
    "PushRuleUpdateMixin",
]
