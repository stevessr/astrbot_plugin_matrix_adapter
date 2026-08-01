"""Matrix device identity and manager helpers."""

from ...storage.stores.device import MatrixDeviceManager


class MatrixConfigDeviceMixin:
    """Manage the Matrix device ID used by the client."""

    @property
    def device_id(self) -> str:
        """获取设备 ID，如果不存在则自动生成"""
        if self._device_id is None:
            self._ensure_device_manager()
            self._device_id = self._device_manager.get_or_create_device_id()
        return self._device_id

    def _ensure_device_manager(self):
        """确保设备管理器已初始化"""
        if self._device_manager is None and self.user_id:
            # 使用插件级别配置的存储路径
            self._device_manager = MatrixDeviceManager(
                user_id=self.user_id,
                homeserver=self.homeserver,
                store_path=self.store_path,
            )

    def set_device_id(self, device_id: str):
        """设置设备 ID"""
        self._ensure_device_manager()
        self._device_manager.set_device_id(device_id)
        self._device_id = device_id

    def reset_device_id(self) -> str:
        """重置设备 ID（生成新的设备 ID）"""
        self._ensure_device_manager()
        self._device_id = self._device_manager.reset_device_id()
        return self._device_id
