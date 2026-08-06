"""Device storage load operations."""

from astrbot.api import logger


class MatrixDevicePersistenceLoadMixin:
    """Load and validate persisted device information."""

    def _load_device_info(self) -> dict | None:
        """
        从磁盘加载设备信息

        Returns:
            设备信息字典，如果不存在则返回 None
        """
        try:
            device_info = self._device_store.get("device_info")
            if not isinstance(device_info, dict):
                return None

            # 验证设备信息是否匹配当前用户和服务器
            if (
                device_info.get("user_id") != self.user_id
                or device_info.get("homeserver") != self.homeserver
            ):
                logger.warning(
                    "存储的设备信息与当前用户/服务器不匹配，将生成新的设备 ID",
                    extra={"plugin_tag": "matrix", "short_levelname": "WARN"},
                )
                return None

            logger.debug(
                f"从磁盘加载设备信息：device_id={device_info.get('device_id')}",
                extra={"plugin_tag": "matrix", "short_levelname": "DBUG"},
            )

            return device_info

        except Exception as e:
            logger.error(
                f"加载设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )
            return None


__all__ = ["MatrixDevicePersistenceLoadMixin"]
