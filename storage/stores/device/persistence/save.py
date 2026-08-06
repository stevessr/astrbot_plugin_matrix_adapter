"""Device storage save operations."""

import time

from astrbot.api import logger


class MatrixDevicePersistenceSaveMixin:
    """Persist device information to storage."""

    def _save_device_info(self, device_id: str):
        """
        保存设备信息到磁盘

        Args:
            device_id: 要保存的设备 ID
        """
        try:
            device_info = {
                "device_id": device_id,
                "user_id": self.user_id,
                "homeserver": self.homeserver,
                "created_at": int(time.time() * 1000),  # 毫秒时间戳
            }
            self._device_store.upsert("device_info", device_info)

            logger.debug(
                f"设备信息已保存（backend={self._storage_backend}）",
                extra={"plugin_tag": "matrix", "short_levelname": "DBUG"},
            )

        except Exception as e:
            logger.error(
                f"保存设备信息失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )


__all__ = ["MatrixDevicePersistenceSaveMixin"]
