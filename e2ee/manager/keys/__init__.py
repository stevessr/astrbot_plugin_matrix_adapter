"""Composable E2EE manager device-key and maintenance operations."""

import time

from astrbot.api import logger

from ....constants import (
    DEFAULT_ONE_TIME_KEYS_COUNT,
    MEGOLM_ALGO,
    OLM_ALGO,
    SIGNED_CURVE25519,
)
from .device import E2EEManagerDeviceKeysMixin
from .maintenance import E2EEManagerKeyMaintenanceMixin


class E2EEManagerKeysMixin(
    E2EEManagerDeviceKeysMixin,
    E2EEManagerKeyMaintenanceMixin,
):
    """上传设备密钥并维护一次性密钥。"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
E2EEManagerKeysMixin._upload_device_keys = (
    E2EEManagerDeviceKeysMixin._upload_device_keys
)
E2EEManagerKeysMixin._get_server_key_counts = (
    E2EEManagerKeyMaintenanceMixin._get_server_key_counts
)
E2EEManagerKeysMixin.ensure_sufficient_one_time_keys = (
    E2EEManagerKeyMaintenanceMixin.ensure_sufficient_one_time_keys
)


__all__ = [
    "DEFAULT_ONE_TIME_KEYS_COUNT",
    "E2EEManagerDeviceKeysMixin",
    "E2EEManagerKeyMaintenanceMixin",
    "E2EEManagerKeysMixin",
    "MEGOLM_ALGO",
    "OLM_ALGO",
    "SIGNED_CURVE25519",
    "logger",
    "time",
]
