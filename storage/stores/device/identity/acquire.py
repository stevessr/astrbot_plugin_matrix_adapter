"""Device ID acquisition and rotation."""

from astrbot.api import logger


class MatrixDeviceIdentityAcquireMixin:
    """Acquire, reset, and set device IDs."""

    def get_or_create_device_id(self, force_new: bool = False) -> str:
        """
        获取现有设备 ID 或创建新的设备 ID

        Args:
            force_new: 是否强制生成新的设备 ID

        Returns:
            设备 ID
        """
        # 如果已经有缓存的设备 ID 且不强制重新生成，直接返回
        if self._device_id and not force_new:
            return self._device_id

        # 尝试从磁盘加载现有设备信息
        if not force_new:
            device_info = self._load_device_info()
            if device_info and "device_id" in device_info:
                self._device_id = device_info["device_id"]
                logger.info(
                    f"使用已存储的设备 ID: {self._device_id}",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
                return self._device_id

        # 生成新的设备 ID
        self._device_id = self._generate_device_id()

        # 保存到磁盘
        self._save_device_info(self._device_id)

        return self._device_id

    def get_device_id(self) -> str | None:
        """
        获取当前设备 ID（不自动生成）

        Returns:
            当前设备 ID，如果不存在则返回 None
        """
        if self._device_id:
            return self._device_id

        device_info = self._load_device_info()
        if device_info and "device_id" in device_info:
            self._device_id = device_info["device_id"]

        return self._device_id

    def reset_device_id(self) -> str:
        """
        重置设备 ID（生成新的设备 ID）

        Returns:
            新的设备 ID
        """
        logger.info(
            "重置 Matrix 设备 ID",
            extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
        )
        return self.get_or_create_device_id(force_new=True)

    def set_device_id(self, device_id: str):
        """设置设备 ID"""
        self._device_id = device_id
        # 保存完整的设备信息（包括 user_id 和 homeserver 用于验证）
        self._save_device_info(device_id)


__all__ = ["MatrixDeviceIdentityAcquireMixin"]
