"""Device storage delete operations."""

from astrbot.api import logger


class MatrixDevicePersistenceDeleteMixin:
    """Delete persisted device information."""

    def delete_device_info(self):
        """删除存储的设备信息"""
        try:
            self._device_store.delete("device_info")
            logger.info(
                "已删除存储的设备信息",
                extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
            )
            self._device_id = None
        except Exception as e:
            logger.error(
                f"删除设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )


__all__ = ["MatrixDevicePersistenceDeleteMixin"]
