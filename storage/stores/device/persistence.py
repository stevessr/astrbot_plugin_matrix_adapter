"""Device storage persistence operations."""

import time

from astrbot.api import logger

from ...backend import MatrixFolderDataStore


class MatrixDevicePersistenceMixin:
    """Persist and validate Matrix device information."""

    @staticmethod
    def _device_json_filename(_: str) -> str:
        return "device_info.json"

    def _build_device_store(self, namespace: str) -> MatrixFolderDataStore:
        try:
            return MatrixFolderDataStore(
                folder_path=self.user_store_path,
                namespace_key=namespace,
                backend=self._storage_backend,
                json_filename_resolver=self._device_json_filename,
                pgsql_dsn=self._pgsql_dsn,
                pgsql_schema=self._pgsql_schema,
                pgsql_table_prefix=self._pgsql_table_prefix,
            )
        except Exception as e:
            logger.warning(
                f"初始化设备存储后端 {self._storage_backend} 失败，回退 json: {e}"
            )
            return MatrixFolderDataStore(
                folder_path=self.user_store_path,
                namespace_key=namespace,
                backend="json",
                json_filename_resolver=self._device_json_filename,
            )

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
