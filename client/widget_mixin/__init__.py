"""Composable Matrix widget management operations."""

from typing import Any

from astrbot.api import logger

from .listing import WidgetListingMixin
from .operations import WidgetOperationsMixin


class WidgetMixin(
    WidgetListingMixin,
    WidgetOperationsMixin,
):
    """Widget management methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
WidgetMixin.get_widgets = WidgetListingMixin.__dict__["get_widgets"]
WidgetMixin.add_widget = WidgetOperationsMixin.__dict__["add_widget"]
WidgetMixin.remove_widget = WidgetOperationsMixin.__dict__["remove_widget"]
WidgetMixin.update_widget = WidgetOperationsMixin.__dict__["update_widget"]


__all__ = ["Any", "WidgetMixin", "logger"]
