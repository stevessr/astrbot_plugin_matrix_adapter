"""Composable high-level E2EE manager core."""

import asyncio
from pathlib import Path
from typing import Literal

from astrbot.api import logger

from ....config.plugin import get_plugin_config
from ....storage.backend import build_folder_namespace
from ....storage.paths import MatrixStoragePaths
from ....utils.utils import mask_device_id
from ...constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC,
    DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
)
from ...decrypt import E2EEManagerDecryptMixin
from ...olm import VODOZEMAC_AVAILABLE, OlmMachine
from ...requests import E2EEManagerRequestsMixin
from ...secrets import E2EEManagerSecretsMixin
from ...sessions import E2EEManagerSessionsMixin
from ...store import CryptoStore
from ..keys import E2EEManagerKeysMixin
from ..verification import E2EEManagerVerificationMixin
from .initialization import E2EEManagerCoreInitializationMixin
from .lifecycle import E2EEManagerCoreLifecycleMixin
from .sharing import E2EEManagerCoreKeySharingMixin


class E2EEManager(
    E2EEManagerCoreInitializationMixin,
    E2EEManagerCoreLifecycleMixin,
    E2EEManagerCoreKeySharingMixin,
    E2EEManagerVerificationMixin,
    E2EEManagerKeysMixin,
    E2EEManagerDecryptMixin,
    E2EEManagerRequestsMixin,
    E2EEManagerSecretsMixin,
    E2EEManagerSessionsMixin,
):
    """
    端到端加密管理器

    负责：
    - 初始化加密组件
    - 设备密钥上传
    - 消息加密/解密
    - 密钥交换
    - SAS 设备验证
    - 密钥备份
    - 交叉签名
    """

    pass


# Preserve direct method attributes exposed by the former monolithic module.
E2EEManager._mask_device_id = staticmethod(mask_device_id)
E2EEManager.is_available = E2EEManagerCoreLifecycleMixin.is_available

for _method_name in (
    "__init__",
    "_finalize_own_device_trust",
    "_apply_key_backup_preference",
    "initialize",
):
    setattr(
        E2EEManager,
        _method_name,
        getattr(E2EEManagerCoreInitializationMixin, _method_name),
    )

for _method_name in (
    "_start_key_share_check_task",
    "_handle_key_share_check_task_done",
    "stop_key_share_check_task",
    "close",
):
    setattr(
        E2EEManager,
        _method_name,
        getattr(E2EEManagerCoreLifecycleMixin, _method_name),
    )

E2EEManager._proactive_check_key_sharing = (
    E2EEManagerCoreKeySharingMixin._proactive_check_key_sharing
)


__all__ = [
    "CryptoStore",
    "DEFAULT_OLM_RECOVERY_RETRY_SEC",
    "DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC",
    "DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC",
    "DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC",
    "DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC",
    "E2EEManager",
    "E2EEManagerCoreInitializationMixin",
    "E2EEManagerCoreKeySharingMixin",
    "E2EEManagerCoreLifecycleMixin",
    "E2EEManagerDecryptMixin",
    "E2EEManagerKeysMixin",
    "E2EEManagerRequestsMixin",
    "E2EEManagerSecretsMixin",
    "E2EEManagerSessionsMixin",
    "E2EEManagerVerificationMixin",
    "Literal",
    "MatrixStoragePaths",
    "OlmMachine",
    "Path",
    "VODOZEMAC_AVAILABLE",
    "asyncio",
    "build_folder_namespace",
    "get_plugin_config",
    "logger",
    "mask_device_id",
]
