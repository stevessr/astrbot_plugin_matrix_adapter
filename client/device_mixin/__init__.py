"""Composable Matrix device management operations."""

from typing import Any

from ..path_utils import quote_path_segment
from .lifecycle import DeviceLifecycleMixin
from .listing import DeviceListingMixin


class DeviceMixin(
    DeviceListingMixin,
    DeviceLifecycleMixin,
):
    """Device management methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
DeviceMixin.get_devices = DeviceListingMixin.__dict__["get_devices"]
DeviceMixin.get_device = DeviceListingMixin.__dict__["get_device"]
DeviceMixin.update_device = DeviceLifecycleMixin.__dict__["update_device"]
DeviceMixin.delete_device = DeviceLifecycleMixin.__dict__["delete_device"]
DeviceMixin.delete_devices = DeviceLifecycleMixin.__dict__["delete_devices"]


__all__ = ["Any", "DeviceMixin", "quote_path_segment"]
