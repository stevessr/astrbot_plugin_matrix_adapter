"""Matrix widget add, remove, and update operations."""

from .add import WidgetAddMixin
from .remove import WidgetRemoveMixin
from .update import WidgetUpdateMixin


class WidgetOperationsMixin(
    WidgetAddMixin,
    WidgetRemoveMixin,
    WidgetUpdateMixin,
):
    """Create, remove, and update room widgets."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    WidgetAddMixin,
    WidgetRemoveMixin,
    WidgetUpdateMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(WidgetOperationsMixin, _method_name, _method)


__all__ = [
    "WidgetAddMixin",
    "WidgetOperationsMixin",
    "WidgetRemoveMixin",
    "WidgetUpdateMixin",
]
