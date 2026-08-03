"""Composable Matrix device storage operations."""

import base64
import secrets
import time
from pathlib import Path

from astrbot.api import logger

from ....config.plugin import get_plugin_config
from ...backend import MatrixFolderDataStore, build_folder_namespace
from .identity import MatrixDeviceIdentityMixin
from .persistence import MatrixDevicePersistenceMixin


class MatrixDeviceManager(
    MatrixDevicePersistenceMixin,
    MatrixDeviceIdentityMixin,
):
    """Matrix 设备 ID 管理器。"""

    def __init__(
        self,
        user_id: str,
        homeserver: str,
        store_path: str | Path,
    ):
        """
        初始化设备管理器

        Args:
            user_id: Matrix 用户 ID
            homeserver: Matrix 服务器地址
            store_path: 存储路径
        """

        self.user_id = user_id

        self.homeserver = homeserver.rstrip("/")

        self.store_path = Path(store_path)
        self._storage_backend_config = get_plugin_config().storage_backend_config
        self._storage_backend = self._storage_backend_config.backend
        self._pgsql_dsn = self._storage_backend_config.pgsql_dsn
        self._pgsql_schema = self._storage_backend_config.pgsql_schema
        self._pgsql_table_prefix = self._storage_backend_config.pgsql_table_prefix

        # 使用新的存储路径逻辑

        from ...paths import MatrixStoragePaths

        # 获取用户的存储目录

        self.user_store_path = MatrixStoragePaths.get_user_storage_dir(
            store_path, homeserver, user_id
        )

        # 确保目录存在

        MatrixStoragePaths.ensure_directory(self.user_store_path, treat_as_file=False)

        # 设备信息文件路径

        self.device_info_path = self.user_store_path / "device_info.json"
        namespace = build_folder_namespace(self.user_store_path, self.store_path)
        self._device_store = self._build_device_store(namespace)

        self._device_id: str | None = None


# Preserve direct method attributes exposed by the former monolithic module.
for _mixin in (MatrixDevicePersistenceMixin, MatrixDeviceIdentityMixin):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixDeviceManager, _method_name, _method)


__all__ = [
    "MatrixDeviceIdentityMixin",
    "MatrixDeviceManager",
    "MatrixDevicePersistenceMixin",
    "MatrixFolderDataStore",
    "base64",
    "build_folder_namespace",
    "get_plugin_config",
    "logger",
    "secrets",
    "time",
]
