"""Composable cross-signing key restoration operations."""

import base64

from astrbot.api import logger

from ....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)
from ...constants import (
    DEVICE_SECRET_REQUEST_FAILED,
    DEVICE_SECRET_REQUEST_NOT_NEEDED,
    DEVICE_SECRET_REQUEST_PENDING,
    DEVICE_SECRET_REQUEST_UNAVAILABLE,
)
from .devices import CrossSigningRestoreDevicesMixin
from .local import CrossSigningRestoreLocalMixin
from .secrets import CrossSigningRestoreSecretsMixin
from .server import CrossSigningRestoreServerMixin


class CrossSigningRestoreMixin(
    CrossSigningRestoreLocalMixin,
    CrossSigningRestoreServerMixin,
    CrossSigningRestoreSecretsMixin,
    CrossSigningRestoreDevicesMixin,
):
    """本地密钥加载/保存/恢复"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_load_local_keys",
    "_save_local_keys",
    "persist_local_keys",
    "_restore_keys",
):
    setattr(
        CrossSigningRestoreMixin,
        _method_name,
        getattr(CrossSigningRestoreLocalMixin, _method_name),
    )

for _method_name in (
    "_query_server_cross_signing_state",
    "_has_private_keys_for_server_state",
    "_missing_cross_signing_secret_names",
):
    setattr(
        CrossSigningRestoreMixin,
        _method_name,
        getattr(CrossSigningRestoreServerMixin, _method_name),
    )

for _method_name in (
    "_restore_private_keys_from_secret_storage",
    "_write_private_keys_to_secret_storage",
):
    setattr(
        CrossSigningRestoreMixin,
        _method_name,
        getattr(CrossSigningRestoreSecretsMixin, _method_name),
    )

CrossSigningRestoreMixin._request_missing_private_keys_from_devices = (
    CrossSigningRestoreDevicesMixin._request_missing_private_keys_from_devices
)


__all__ = [
    "CrossSigningRestoreDevicesMixin",
    "CrossSigningRestoreLocalMixin",
    "CrossSigningRestoreMixin",
    "CrossSigningRestoreSecretsMixin",
    "CrossSigningRestoreServerMixin",
    "DEVICE_SECRET_REQUEST_FAILED",
    "DEVICE_SECRET_REQUEST_NOT_NEEDED",
    "DEVICE_SECRET_REQUEST_PENDING",
    "DEVICE_SECRET_REQUEST_UNAVAILABLE",
    "SECRET_CROSS_SIGNING_MASTER",
    "SECRET_CROSS_SIGNING_SELF_SIGNING",
    "SECRET_CROSS_SIGNING_USER_SIGNING",
    "base64",
    "logger",
]
