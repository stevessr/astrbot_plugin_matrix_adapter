"""Composable cross-signing core state and lifecycle support."""

from collections.abc import Awaitable, Callable
from pathlib import Path

from astrbot.api import logger

from ....config.plugin import get_plugin_config
from ...backup.crypto_utils import CRYPTO_AVAILABLE
from ...constants import DEVICE_SECRET_REQUEST_PENDING, FORCE_OVERWRITE_SERVER_KEYS
from ...storage import build_e2ee_data_store
from .initialization import CrossSigningCoreInitializationMixin
from .state import CrossSigningCoreStateMixin


class CrossSigningCoreMixin(
    CrossSigningCoreStateMixin,
    CrossSigningCoreInitializationMixin,
):
    """
    交叉签名管理器

    使用 vodozemac/ed25519 进行真正的签名操作
    """

    pass


# Preserve direct properties and methods exposed by the former monolithic module.
CrossSigningCoreMixin._RECORD_CROSS_SIGNING = (
    CrossSigningCoreStateMixin._RECORD_CROSS_SIGNING
)
for _property_name in (
    "has_master_key",
    "master_key",
    "self_signing_key",
    "device_key_id",
    "master_private_key",
    "self_signing_private_key",
    "user_signing_private_key",
):
    setattr(
        CrossSigningCoreMixin,
        _property_name,
        CrossSigningCoreStateMixin.__dict__[_property_name],
    )

CrossSigningCoreMixin._json_filename_resolver = staticmethod(
    CrossSigningCoreStateMixin.__dict__["_json_filename_resolver"].__func__
)

for _method_name in ("__init__", "initialize"):
    setattr(
        CrossSigningCoreMixin,
        _method_name,
        getattr(CrossSigningCoreInitializationMixin, _method_name),
    )


__all__ = [
    "Awaitable",
    "CRYPTO_AVAILABLE",
    "Callable",
    "CrossSigningCoreInitializationMixin",
    "CrossSigningCoreMixin",
    "CrossSigningCoreStateMixin",
    "DEVICE_SECRET_REQUEST_PENDING",
    "FORCE_OVERWRITE_SERVER_KEYS",
    "Path",
    "build_e2ee_data_store",
    "get_plugin_config",
    "logger",
]
