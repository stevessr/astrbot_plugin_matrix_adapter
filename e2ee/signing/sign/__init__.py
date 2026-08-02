"""Composable cross-signing signature operations."""

import copy

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from .device import CrossSigningDeviceSignMixin
from .master import CrossSigningMasterSignMixin
from .user import CrossSigningUserVerifyMixin


class CrossSigningSignMixin(
    CrossSigningDeviceSignMixin,
    CrossSigningMasterSignMixin,
    CrossSigningUserVerifyMixin,
):
    """设备/用户签名：设备签名、master key 设备签名、用户验证"""

    pass


# Keep the legacy methods directly visible on the combined mixin.  Some
# integrations inspect this module/class instead of relying on MRO lookup.
for _method_name, _method_owner in (
    ("sign_device", CrossSigningDeviceSignMixin),
    ("sign_master_key_with_device", CrossSigningMasterSignMixin),
    ("verify_user", CrossSigningUserVerifyMixin),
):
    setattr(CrossSigningSignMixin, _method_name, _method_owner.__dict__[_method_name])


__all__ = [
    "CrossSigningSignMixin",
    "CrossSigningDeviceSignMixin",
    "CrossSigningMasterSignMixin",
    "CrossSigningUserVerifyMixin",
    "copy",
    "logger",
    "MatrixAPIError",
]
