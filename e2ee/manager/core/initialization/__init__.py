"""Composable manager construction, trust, backup, and startup initialization."""

import asyncio
from pathlib import Path
from typing import Literal

from astrbot.api import logger

from .....storage.backend import (
    build_folder_namespace as _DEFAULT_BUILD_FOLDER_NAMESPACE,
)
from .....storage.paths import MatrixStoragePaths as _DEFAULT_MATRIX_STORAGE_PATHS
from ....constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC,
    DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
)
from ....olm import OlmMachine
from ....olm import OlmMachine as _DEFAULT_OLM_MACHINE
from ....store import CryptoStore
from ....store import CryptoStore as _DEFAULT_CRYPTO_STORE
from ..compat import resolve_manager_symbol, resolve_plugin_config, vodozemac_available
from .backup import E2EEManagerCoreInitializationBackupMixin
from .constructor import E2EEManagerCoreInitializationConstructorMixin
from .startup import E2EEManagerCoreInitializationStartupMixin
from .trust import E2EEManagerCoreInitializationTrustMixin


class E2EEManagerCoreInitializationMixin(
    E2EEManagerCoreInitializationConstructorMixin,
    E2EEManagerCoreInitializationTrustMixin,
    E2EEManagerCoreInitializationBackupMixin,
    E2EEManagerCoreInitializationStartupMixin,
):
    """初始化 E2EE 组件并完成本机信任配置。"""

    pass


# Preserve direct method attributes exposed by the former mixin.
E2EEManagerCoreInitializationMixin.__init__ = (
    E2EEManagerCoreInitializationConstructorMixin.__init__
)
E2EEManagerCoreInitializationMixin._finalize_own_device_trust = (
    E2EEManagerCoreInitializationTrustMixin._finalize_own_device_trust
)
E2EEManagerCoreInitializationMixin._apply_key_backup_preference = (
    E2EEManagerCoreInitializationBackupMixin._apply_key_backup_preference
)
E2EEManagerCoreInitializationMixin.initialize = (
    E2EEManagerCoreInitializationStartupMixin.initialize
)


__all__ = [
    "CryptoStore",
    "DEFAULT_OLM_RECOVERY_RETRY_SEC",
    "DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC",
    "DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC",
    "DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC",
    "DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC",
    "E2EEManagerCoreInitializationBackupMixin",
    "E2EEManagerCoreInitializationConstructorMixin",
    "E2EEManagerCoreInitializationMixin",
    "E2EEManagerCoreInitializationStartupMixin",
    "E2EEManagerCoreInitializationTrustMixin",
    "Literal",
    "OlmMachine",
    "Path",
    "_DEFAULT_BUILD_FOLDER_NAMESPACE",
    "_DEFAULT_CRYPTO_STORE",
    "_DEFAULT_MATRIX_STORAGE_PATHS",
    "_DEFAULT_OLM_MACHINE",
    "asyncio",
    "logger",
    "resolve_manager_symbol",
    "resolve_plugin_config",
    "vodozemac_available",
]
